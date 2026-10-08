"""관문 바인딩·실행·합성 (FR-P01·P02·P04) — `judge:batch`, 판정 시뮬레이터(SCR-D05), 정책 단위 시험(SCR-D04)이
같은 경로를 쓴다. 그래서 시뮬레이션·시험 결과는 실제 관문 판정과 같다. 이 모듈은 아무것도 저장하지 않는다."""
from __future__ import annotations

import bisect
import itertools
import logging
import threading
from concurrent.futures import Future, wait
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.schemas import VERDICT_RANK, JudgeRequest
from app import hotcache, models, orchestrator, policy, profiles, registry, scanner
from app.core.config import settings

log = logging.getLogger("aegismesh.gating")
_async: set[Future] = set()


class GateError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def runtime(s: Session, agent_id: str):
    a = s.get(models.Agent, agent_id)
    if not a:
        raise GateError(404, f"agent {agent_id} 없음")
    if a.status not in profiles.BINDABLE:
        raise GateError(409, f"agent {agent_id} 실행 불가 (status={a.status}, origin={a.origin})")
    return registry.runtime_agent(agent_id, a.origin), a


def bind(s: Session, tenant: str, agent_ids: list[str] | None, target: str | None):
    """에이전트 지정이 없으면 테넌트의 활성 프로파일 적용을 따른다."""
    application = None
    if agent_ids is None:
        application = hotcache.get(("app", tenant, target),
                                   lambda: hotcache.detach(s, profiles.active_for(s, tenant, target)))
        if not application:
            raise GateError(409, f"테넌트 {tenant} 에 적용된 프로파일 없음 — /v1/profiles/{{id}}:apply 먼저")
        agent_ids = application.agent_ids

    def load():                                       # 한 번에 조회 → 떼어 낸 스냅샷
        rows = list(s.scalars(select(models.Agent).where(models.Agent.id.in_(agent_ids))))
        for a in rows:
            hotcache.detach(s, a)
        return {a.id: a for a in rows}
    found = hotcache.get(("agents", tuple(sorted(agent_ids))), load)
    out = {}
    for i in agent_ids:
        a = found.get(i)
        if not a:
            raise GateError(404, f"agent {i} 없음")
        if a.status not in profiles.BINDABLE:
            raise GateError(409, f"agent {i} 실행 불가 (status={a.status}, origin={a.origin})")
        out[i] = (registry.runtime_agent(i, a.origin), a)
    return application, out


def run(gate: str, req: JudgeRequest, rows: dict, spec: policy.PolicySpec | None = None, strict: bool = True) -> dict:
    """관문에 바인딩된 에이전트 실행 — 정책 agentParams 적용, relocated(상시 계열로 재배치) 에이전트는 인라인에서 뺀다."""
    moved = set(spec.relocated) if spec else set()
    here = [rt for rt, row in rows.values() if row.gate == gate]
    out = orchestrator.run_gate(gate, req, [rt for rt in here if rt.id not in moved], spec.agent_params if spec else None, strict)
    out["relocated"] = [rt.id for rt in here if rt.id in moved]
    return out


def decide(s: Session, tenant: str, req: JudgeRequest, run_: dict, rows: dict,
           application: models.ProfileApplication | None, spec: policy.PolicySpec, stage: str):
    """정책·프로파일 재정의·오탐 예산 강등·격리 목록을 합성한 관문 결정."""
    extra = hotcache.get(("ovr", application.profile_id), lambda: profiles.overrides(s, application.profile_id)) if application else {}
    alert_only = frozenset(i for i, (_, row) in rows.items() if row.status == "alert_only")
    decision = policy.evaluate(run_["findings"], spec, stage, extra, alert_only)
    quarantined = scanner.match(s, tenant, req)        # 상시 점검 발견 → 인라인 정책 동적 변경 (PRD §8.2)
    if quarantined is not None:
        decision["decisions"].append({"findingId": None, "agent": "platform", "ruleId": "PLATFORM.quarantine",
                                      "original": "block", "effective": "block",
                                      "reasons": [f"격리 목록 {quarantined.id}: {quarantined.kind} '{quarantined.value}' — {quarantined.reason}"],
                                      "degraded": False})
        decision["verdict"] = "block"
    return decision, quarantined


# ── 요청 모양 (원문 없이 — 판정 기록·상세 화면용, NFR-D1) ─────────────────
MAX_ITEMS = 50


def _script(t: str) -> str:
    """문자 체계만(원문 아님) — 언어 집단 축의 기본값: ko(한글 위주)·latin·mixed·other."""
    letters = [c for c in t[:2000] if c.isalpha()]
    if not letters:
        return "other"
    ko = sum("가" <= c <= "힣" for c in letters) / len(letters)
    la = sum(c.isascii() for c in letters) / len(letters)
    return "ko" if ko >= 0.6 else "latin" if la >= 0.6 else "mixed" if ko + la >= 0.6 else "other"


def shape(req: JudgeRequest) -> dict:
    """원문 없이 요청의 구조만 — 세그먼트 출처·신뢰·길이, 검색 문서·메모리 메타데이터, 도구 이름·인자 키, 목표 해시.
    입력 검사 뷰어(SCR-E02)·접근 결정(F03)·도구 호출 상세(G02)·메모리 탐색(L02)이 원장 기록에서 읽는다."""
    import hashlib
    out: dict = {k: len(v) for k, v in (("text", req.text), ("system", req.system), ("output", req.output)) if v}
    if req.segments:
        out["segments"] = [{"i": i, "source": g.source, "trust": g.trust, "chars": len(g.text)} for i, g in enumerate(req.segments[:MAX_ITEMS])]
    if req.retrieval:
        out["retrieval"] = [{"id": d.id, "source": d.source, "url": d.url, "tenant": d.tenant, "owner": d.owner, "acl": d.acl,
                             "signed": d.signed, "trust": d.trust} for d in req.retrieval[:MAX_ITEMS]]
    if req.memory:
        out["memory"] = [{"id": m.id, "tenant": m.tenant, "owner": m.owner, "session": m.session, "writer": m.writer,
                          "approved": m.approved, "ttlSec": m.ttl_sec} for m in req.memory[:MAX_ITEMS]]
    if req.tool:
        out["tool"] = {"name": req.tool.name, "args": sorted(req.tool.args)[:MAX_ITEMS], "approved": req.tool.approved,
                       "requiredScopes": req.tool.required_scopes}
    if req.goal:
        out["goalHash"] = hashlib.sha256(req.goal.encode()).hexdigest()[:16]
    if req.plan:
        out["planSteps"] = len(req.plan)
    if req.action:
        out["action"] = req.action.model_dump(by_alias=True, exclude_none=True)
    h8 = lambda v: hashlib.sha256(str(v).encode()).hexdigest()[:8]    # noqa: E731 — 가명 식별(재사용 탐지용), 원값 아님
    if (p := req.subject.principal):
        out["principal"] = p.id
        out["principalMeta"] = {"type": p.type, "roles": p.roles[:20], "scopes": p.scopes[:50], "spiffe": bool(p.spiffe_id)}
    if (o := req.subject.on_behalf_of):
        out["onBehalfOf"] = o.id
        out["agentMeta"] = {"type": o.type, "roles": o.roles[:20], "scopes": o.scopes[:50], "spiffe": bool(o.spiffe_id)}
    if (a := req.auth):
        c = a.token_claims or {}
        aud = c.get("aud")
        out["auth"] = {"method": a.method, "mfa": a.mfa, "signed": a.signed_identity, "attested": bool(a.attested_spiffe_id),
                       "aud": (aud if isinstance(aud, list) else [aud] if aud else [])[:5], "azp": c.get("azp") or c.get("client_id"),
                       "lifetimeSec": (c["exp"] - c["iat"]) if isinstance(c.get("exp"), (int, float)) and isinstance(c.get("iat"), (int, float)) else None,
                       "exp": c.get("exp") if isinstance(c.get("exp"), (int, float)) else None, "jti": h8(c["jti"]) if c.get("jti") else None,
                       "cnf": "dpop" if (c.get("cnf") or {}).get("jkt") else "mtls" if (c.get("cnf") or {}).get("x5t#S256") else None}
    if req.history:
        out["history"] = [{k: h.get(k) for k in ("agent", "parent", "depth", "tool", "stateHash", "principal") if h.get(k) is not None}
                          for h in req.history[-MAX_ITEMS:]]
    for k in ("destination", "provenance", "zone"):                 # 판정에 쓰인 문맥 값(원문 아님)
        if isinstance(req.params.get(k), (str, int, float)):
            out[k] = str(req.params[k])[:120]
    if req.subject.groups:                                           # 공정성 집계(SCR-N06) — 가명 범주 라벨
        out["groups"] = dict(req.subject.groups)
    if (t := req.text or req.output):
        out["script"] = _script(t)
    if req.subject.resource:
        out["resource"] = {k: str(v)[:80] for k, v in list(req.subject.resource.items())[:10]}
    if (se := req.session):
        out["session"] = se.id
        out["sessionMeta"] = {"bound": bool(se.bound_fingerprint or se.bound_ip),
                              "fpChanged": bool(se.bound_fingerprint and se.fingerprint and se.bound_fingerprint != se.fingerprint),
                              "ipChanged": bool(se.bound_ip and se.ip and se.bound_ip != se.ip),
                              "ip": h8(se.ip) if se.ip else None, "fp": h8(se.fingerprint) if se.fingerprint else None}
    return out


# ── 재배치 에이전트 (SCR-D02 — 지연 예산 초과 → 상시 계열 비동기) ─────────────
def run_relocated(tenant: str, gate: str, req: JudgeRequest, rows: dict, ids: list[str], spec: policy.PolicySpec,
                  stage: str) -> None:
    """응답을 돌려준 뒤 재배치 에이전트를 시간 제한 없이 판정한다. 유효 판정은 최대 alert(응답 후 표시 — 차단 불가),
    판정은 Finding + 원장 gate_async 기록으로 남는다(인라인 관문 기록·지연 통계와 섞지 않음)."""
    rts = [rows[i][0] for i in ids if i in rows]
    if not rts:
        return

    def job():
        from app import evidence_writer, findings, ledger
        from app.db import system_session
        try:
            base = req.model_copy(update={"gate": gate})
            fs = [rt.judge(orchestrator.agent_request(rt, base, spec.agent_params)) for rt in rts]
            dec = policy.evaluate(fs, spec, stage)
            for d in dec["decisions"]:
                if VERDICT_RANK[d["effective"]] > VERDICT_RANK["alert"]:
                    d["reasons"].append("재배치(상시 계열) — 응답 후 판정, 차단 불가")
                    d["effective"] = "alert"
            verdict = max((d["effective"] for d in dec["decisions"]), key=VERDICT_RANK.__getitem__, default="allow")
            eff = {d["findingId"]: d["effective"] for d in dec["decisions"]}
            record = ("gate_async", req.trace_id, {"gate": gate, "traceId": req.trace_id, "relocated": True, "verdict": verdict,
                                                   "agents": [f.agent.id for f in fs], "decisions": dec["decisions"],
                                                   "latencyMs": round(sum(f.latency_ms for f in fs), 3)})
            if evidence_writer.enabled():
                evidence_writer.submit(evidence_writer.Item(tenant, verdict, [record], [(f, eff[f.id]) for f in fs]))
            else:
                with system_session() as s2:
                    for f in fs:
                        findings.store(s2, f, eff[f.id])
                    ledger.append(s2, *record, tenant)
                    s2.commit()
        except Exception:  # noqa: BLE001 — 비동기 판정 실패는 요청 경로에 영향 없음(기록만)
            log.exception("relocated agents %s failed", ids)

    fut = orchestrator._POOL.submit(job)
    _async.add(fut)
    fut.add_done_callback(_async.discard)


def drain(timeout: float = 5.0) -> None:
    """대기 중인 재배치 판정을 기다린다(시험·종료용)."""
    wait(list(_async), timeout=timeout)


# ── D1-03 깊은 검사 (Epic 50·51 · OQ9) — 안전 분류 모델은 인라인 예산(30ms)에 못 들어가 응답 뒤 전용 작업자가 본다 ────────
# 선별: 대기열은 인라인 n-gram 분류기 점수가 높은 입력부터 꺼내고, 가득 차면 점수가 가장 낮은 것을 뺀다(모델 처리량은 CPU 초당 1건 안팎).
# 경보: 같은 주체·세션을 기한부로 격리 → 다음 요청부터 인라인 차단(scanner.match). 해제는 2인 승인(quarantine_release).
DEEP_AGENT, DEEP_ENGINE, DEEP_FAST = "d1-03", "jailbreak_guard", "jailbreak_classifier"
DEEP_STATS = {"submitted": 0, "checked": 0, "alerts": 0, "quarantined": 0, "skipped": 0, "evicted": 0, "failed": 0,
              "backlog": 0, "maxBacklog": 0}
_deep_lock = threading.Lock()
_deep_cv = threading.Condition(_deep_lock)
_deep_q: list[tuple[float, int, object, Future]] = []          # (우선순위, 순번, 작업, Future) — 우선순위 오름차순
_deep_seq = itertools.count()
_deep_workers: list[threading.Thread] = []


def _deep_worker() -> None:
    while True:
        with _deep_cv:
            while not _deep_q:
                _deep_cv.wait()
            _, _, fn, fut = _deep_q.pop()                             # 점수가 가장 높은 것
            DEEP_STATS["backlog"] = len(_deep_q)
        if fut.set_running_or_notify_cancel():
            try:
                fn()
                fut.set_result(None)
            except BaseException as e:  # noqa: BLE001
                fut.set_exception(e)


def _deep_submit(priority: float, fn) -> bool:
    fut: Future = Future()
    with _deep_cv:
        while len(_deep_workers) < max(1, settings.guard_workers):
            th = threading.Thread(target=_deep_worker, name=f"deep-{len(_deep_workers)}", daemon=True)
            th.start()
            _deep_workers.append(th)
        if len(_deep_q) >= settings.guard_queue_max:
            if not _deep_q or priority <= _deep_q[0][0]:
                DEEP_STATS["skipped"] += 1                            # 새 입력이 대기열에서 가장 덜 의심스럽다 → 건너뜀
                return False
            _deep_q.pop(0)[3].cancel()                                # 가장 덜 의심스러운 대기 항목을 뺀다
            DEEP_STATS["evicted"] += 1
        bisect.insort(_deep_q, (priority, next(_deep_seq), fn, fut))
        DEEP_STATS["submitted"] += 1
        DEEP_STATS["backlog"] = len(_deep_q)
        DEEP_STATS["maxBacklog"] = max(DEEP_STATS["maxBacklog"], len(_deep_q))
        _deep_cv.notify()
    _async.add(fut)
    fut.add_done_callback(_async.discard)
    return True


def run_deep(tenant: str, gate: str, req: JudgeRequest, rows: dict, spec: policy.PolicySpec, stage: str, verdict: str = "allow") -> None:
    """인라인은 빠른 엔진(규칙 + n-gram 분류기)이 판정했고, 여기서는 안전 분류 모델 포함 엔진으로 다시 본다. 결과는 최대 경보(차단 불가) —
    모델이 새로 잡은 것(D1-03.guard)만 Finding + 원장 gate_async(deep)로 남기고, 그 주체·세션을 기한부 격리한다."""
    if not settings.guard_url or gate != "input" or DEEP_AGENT not in rows or DEEP_AGENT in spec.relocated or verdict != "allow":
        return                                                        # 인라인이 이미 경보·차단했으면 모델 처리량을 쓰지 않는다
    rt = rows[DEEP_AGENT][0]
    fast = rt.engines.get(DEEP_FAST)
    priority = max((fast.module._model().prob(text) for _, text in req.texts("text")), default=0.0) if fast else 0.0

    def job():
        from app import evidence_writer, findings, ledger
        from app.db import system_session
        try:
            f = rt.judge(orchestrator.agent_request(rt, req.model_copy(update={"gate": gate}), spec.agent_params), engine=DEEP_ENGINE)
            with _deep_lock:
                DEEP_STATS["failed" if f.degraded else "checked"] += 1
            if f.degraded or f.rule_id != "D1-03.guard":
                return
            dec = policy.evaluate([f], spec, stage)
            for d in dec["decisions"]:
                if VERDICT_RANK[d["effective"]] > VERDICT_RANK["alert"]:
                    d["effective"] = "alert"
                d["reasons"].append("깊은 검사(안전 분류 모델) — 응답 후 판정, 이 요청은 차단 불가 · 같은 주체·세션의 다음 요청부터 격리")
            verdict = max((d["effective"] for d in dec["decisions"]), key=VERDICT_RANK.__getitem__, default="allow")
            if verdict == "allow":
                return
            qids = []
            if settings.guard_quarantine_sec > 0:
                from datetime import timedelta

                from app import scanner
                until = datetime.now(UTC) + timedelta(seconds=settings.guard_quarantine_sec)
                why = f"깊은 검사(안전 분류 모델) 경보 — 추적 {req.trace_id} · {f.evidence[0].note if f.evidence else ''}"
                with system_session() as s3:
                    for kind, value in (("principal", req.subject.principal.id if req.subject.principal else None),
                                        ("session", req.session.id if req.session else None)):
                        if value:
                            qids.append(scanner.quarantine(s3, tenant, kind, value, why, [f.id], "deep-check", until).id)
                    s3.commit()
            with _deep_lock:
                DEEP_STATS["alerts"] += 1
                DEEP_STATS["quarantined"] += len(qids)
            record = ("gate_async", req.trace_id, {"gate": gate, "traceId": req.trace_id, "deep": True, "engine": DEEP_ENGINE,
                                                   "verdict": verdict, "agents": [f.agent.id], "decisions": dec["decisions"],
                                                   "latencyMs": round(f.latency_ms, 3), "priority": round(priority, 3),
                                                   "quarantined": qids})
            if evidence_writer.enabled():
                evidence_writer.submit(evidence_writer.Item(tenant, verdict, [record], [(f, verdict)]))
            else:
                with system_session() as s2:
                    findings.store(s2, f, verdict)
                    ledger.append(s2, *record, tenant)
                    s2.commit()
        except Exception:  # noqa: BLE001 — 깊은 검사 실패는 요청 경로에 영향 없음(센다)
            with _deep_lock:
                DEEP_STATS["failed"] += 1
            log.exception("deep check failed")

    _deep_submit(priority, job)
