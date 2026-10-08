"""증적 비동기 적재 (NFR-L5) — 인라인 판정은 대기열에 넣고 바로 응답, 전용 스레드가 묶음 트랜잭션으로 체인에 적재.

- 묶음: 체인(테넌트)마다 머리 잠금 1회(ledger.append_many) + 판정 행 일괄 INSERT → 요청 경로에서 체인 잠금 경합이 사라진다.
- 포화: 대기열이 80% 이상이면 표본 적재로 강등 — allow 판정은 N 건 중 1 건만 적재하고 나머지는 계수한다.
  allow 가 아닌 판정(경보·변환·승인·차단)은 강등 중에도 적재. 대기열이 가득 차면 그 건은 버리고 계수한다.
  강등 진입·복귀는 원장(kind=evidence, ref=pipeline)에 남기고 알림으로 올린다. 50% 이하로 내려가면 복귀.
- 일관성: API 는 판정 외 요청 처리 전에 flush() 로 이 프로세스의 대기분을 적재한다(읽기 일관성). 종료 시에도 flush.
  프로세스가 비정상 종료하면 대기열에 남은 건(최대 EVIDENCE_QUEUE_MAX)은 잃는다 — 비동기 적재의 의도된 상충.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field

from aegis.schemas import Finding, now_iso
from app import db, findings, ledger
from app.core.config import settings

log = logging.getLogger("aegismesh.evidence")
HIGH, LOW = 0.8, 0.5


@dataclass
class Item:
    tenant: str
    verdict: str
    records: list[tuple[str, str, dict]]                    # (kind, ref, body) — 판정 기록 등
    findings: list[tuple[Finding, str | None]] = field(default_factory=list)
    incidents: list[dict] = field(default_factory=list)      # 열린 사건 덧붙이기(incidents.apply) — 묶음마다 사건당 한 번 갱신


_q: queue.Queue[Item | None] = queue.Queue(maxsize=max(10, settings.evidence_queue_max))
_lock = threading.Lock()
_thread: threading.Thread | None = None
_events: list[tuple[str, str, dict]] = []                    # 강등·복귀 기록(작성 스레드가 적재)
STATS = {"enqueued": 0, "written": 0, "batches": 0, "sampledOut": 0, "dropped": 0, "failed": 0,
         "degraded": False, "degradedSince": None, "lastBatch": 0, "lastBatchMs": 0.0, "maxDepth": 0}
_window = {"sampledOut": 0, "dropped": 0, "allowSeen": 0, "since": 0.0}


def enabled() -> bool:
    return settings.evidence_async


def _ensure_thread() -> None:
    global _thread
    if _thread is None or not _thread.is_alive():
        with _lock:
            if _thread is None or not _thread.is_alive():
                _thread = threading.Thread(target=_run, name="evidence-writer", daemon=True)
                _thread.start()


def _set_degraded(on: bool, depth: int) -> None:
    """잠금 안에서 호출. 상태가 바뀔 때만 원장 기록을 예약한다."""
    if STATS["degraded"] == on:
        return
    STATS["degraded"] = on
    if on:
        STATS["degradedSince"] = now_iso()
        _window.update(sampledOut=0, dropped=0, allowSeen=0, since=time.time())
        _events.append(("evidence", "pipeline", {"event": "sampling_degraded", "depth": depth, "max": _q.maxsize,
                                                 "sampleEvery": settings.evidence_sample_every,
                                                 "reason": f"적재 대기열 {depth}/{_q.maxsize} ≥ {int(HIGH * 100)}% — allow 판정 표본 적재"}))
        log.warning("증적 적재 강등 — 대기열 %s/%s, allow 판정 1/%s 표본 적재", depth, _q.maxsize, settings.evidence_sample_every)
    else:
        STATS["degradedSince"] = None
        _events.append(("evidence", "pipeline", {"event": "sampling_recovered", "depth": depth,
                                                 "sampledOut": _window["sampledOut"], "dropped": _window["dropped"],
                                                 "durationSec": round(time.time() - _window["since"], 1)}))
        log.warning("증적 적재 복귀 — 표본 제외 %s · 버림 %s", _window["sampledOut"], _window["dropped"])


def submit(item: Item) -> str:
    """대기열에 넣는다. 반환: queued | sampled_out | dropped."""
    _ensure_thread()
    depth = _q.qsize()
    with _lock:
        STATS["maxDepth"] = max(STATS["maxDepth"], depth)
        if depth >= HIGH * _q.maxsize:
            _set_degraded(True, depth)
        elif depth <= LOW * _q.maxsize:
            _set_degraded(False, depth)
        if STATS["degraded"] and item.verdict == "allow":
            _window["allowSeen"] += 1
            if _window["allowSeen"] % settings.evidence_sample_every:
                STATS["sampledOut"] += 1
                _window["sampledOut"] += 1
                return "sampled_out"
    try:
        _q.put_nowait(item)
    except queue.Full:
        with _lock:
            STATS["dropped"] += 1
            _window["dropped"] += 1
        return "dropped"
    with _lock:
        STATS["enqueued"] += 1
    return "queued"


def _write(batch: list[Item]) -> None:
    t0 = time.perf_counter()
    with _lock:
        events, _events[:] = list(_events), []
    by_chain: dict[str, list[tuple[str, str, dict]]] = {}
    rows = []
    for it in batch:
        chain = by_chain.setdefault(it.tenant, [])
        for f, eff in it.findings:
            r = findings.row(f, eff)
            rows.append(r)
            chain.append(("finding", f.id, r.body))
        chain.extend(it.records)
    with db.system_session() as s:
        s.add_all(rows)
        for tenant, items in by_chain.items():
            ledger.append_many(s, tenant, items)
        if events:
            ledger.append_many(s, ledger.PLATFORM, events)
        if deltas := [d for it in batch for d in it.incidents]:
            from app import incidents
            incidents.apply(s, deltas)
        s.commit()
    with _lock:
        STATS["written"] += len(batch)
        STATS["batches"] += 1
        STATS["lastBatch"] = len(batch)
        STATS["lastBatchMs"] = round((time.perf_counter() - t0) * 1000, 2)


def _run() -> None:
    while True:
        first = _q.get()
        if first is None:
            _q.task_done()
            return
        batch = [first]
        while len(batch) < settings.evidence_batch_max:
            try:
                nxt = _q.get_nowait()
            except queue.Empty:
                break
            if nxt is None:
                _q.put_nowait(None)                       # 종료 표지는 이번 묶음 뒤에 처리
                _q.task_done()
                break
            batch.append(nxt)
        try:
            _write(batch)
        except Exception:                                  # noqa: BLE001 — 묶음 실패는 한 건씩 재시도 후 계수
            log.exception("증적 묶음 적재 실패 — 한 건씩 재시도")
            for it in batch:
                try:
                    _write([it])
                except Exception:                          # noqa: BLE001
                    with _lock:
                        STATS["failed"] += 1
                    log.exception("증적 적재 실패 (tenant=%s)", it.tenant)
        finally:
            for _ in batch:
                _q.task_done()
        with _lock:                                        # 대기열이 비면 강등 해제(제출이 끊겨도 복귀 기록)
            if STATS["degraded"] and _q.qsize() <= LOW * _q.maxsize:
                _set_degraded(False, _q.qsize())
            pending = bool(_events)
        if pending and _q.empty():
            try:
                _write([])
            except Exception:                              # noqa: BLE001
                log.exception("증적 강등 기록 적재 실패")


def flush(timeout: float = 5.0) -> bool:
    """이 프로세스의 대기분이 모두 적재될 때까지 기다린다(최대 timeout 초)."""
    if _thread is None:
        return True
    end = time.monotonic() + timeout
    with _q.all_tasks_done:
        while _q.unfinished_tasks:
            left = end - time.monotonic()
            if left <= 0:
                return False
            _q.all_tasks_done.wait(left)
    return True


def shutdown(timeout: float = 10.0) -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        flush(timeout)
        _q.put(None)
        _thread.join(timeout)
    _thread = None


def status() -> dict:
    with _lock:
        return dict(STATS) | {"async": enabled(), "depth": _q.qsize(), "max": _q.maxsize,
                              "sampleEvery": settings.evidence_sample_every, "batchMax": settings.evidence_batch_max,
                              "thresholds": {"degrade": HIGH, "recover": LOW}}
