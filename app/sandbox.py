"""샌드박스 브로커 (FR-P08, NFR-I, SCR-R04) — 격리 등급별 실행 풀, 요청 단위 발급·회수.

| 등급 | 이 설치의 수단 | 상태 |
|---|---|---|
| L0 | API 프로세스 안 (순수 계산 판정) | 항상 |
| L1 | 별도 프로세스 + rlimit + 빈 환경·임시 디렉터리 + Landlock(FS) + seccomp(소켓·exec·fork·ptrace·mount) + 감사 훅 | 커널이 seccomp 를 주면 사용 가능 |
| L2 | 사용자 공간 커널 gVisor(runsc 고정 판) — compose sandbox-l2 브로커(Epic 65) | SANDBOX_L2_URL + 브로커 준비면 사용 가능 |
| L3 | 1회용 microVM | 런타임 없음 → 보류 |

L1 은 에이전트별 상주 하위 프로세스(웜 슬롯)를 요청마다 임대하고, N 회 사용·오류·시간 초과 시 회수(종료·임시 디렉터리 삭제)한다.
L2 는 브로커가 번들별 웜 샌드박스(runsc do, 네트워크 없음·읽기 전용 루트 FS + 1회용 덧씌움)를 같은 규약으로 임대·회수한다.
풀이 고갈되면 대기열에서 기다리다 거부할 뿐 격리 등급을 낮추지 않는다(§8.6). 하위 프로세스는 Decision 만 돌려주고,
Finding 은 부모가 매니페스트로 검증해 만든다 — 에이전트가 다른 에이전트·판정을 사칭할 수 없다.
"""
from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from aegis.agent import Agent, EngineAdapter
from aegis.manifest import Manifest, load_manifest
from aegis.schemas import Decision, JudgeRequest
from app.core.config import settings

ROOT = Path(__file__).resolve().parent.parent
LEVELS = ("L0", "L1", "L2", "L3")
MECHANISM = {"L0": "API 프로세스 안 (순수 계산)", "L1": "별도 프로세스 · rlimit · 빈 환경 · Landlock · seccomp · 감사 훅",
             "L2": "사용자 공간 커널 gVisor (runsc · systrap · 네트워크 없음 · 읽기 전용 루트 FS)", "L3": "1회용 microVM · 스냅샷 후 폐기 · 물리 분리 노드"}
MEM_BYTES = 768 * 1024 * 1024


class SandboxUnavailable(RuntimeError):
    pass


class SandboxBusy(RuntimeError):
    pass


_lock = threading.Lock()
STATS = {lv: {"served": 0, "rejected": 0, "timeouts": 0, "errors": 0, "spawned": 0, "recycled": 0, "queued": 0, "active": 0}
         for lv in LEVELS}
_sem = threading.BoundedSemaphore(max(1, settings.sandbox_l1_slots))


def _bump(level: str, key: str, n: int = 1) -> None:
    with _lock:
        STATS[level][key] += n


def _limits(cpu_sec: int):
    def apply():
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec))
        resource.setrlimit(resource.RLIMIT_AS, (MEM_BYTES, MEM_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
        os.setsid()
    return apply


def _env(tmp: str, level: str) -> dict:
    """빈 환경 — DB 접속 문자열·키·토큰을 넘기지 않는다."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
            "AEGIS_RUNTIME_ISOLATION": level, "HOME": tmp, "SANDBOX_TMP": tmp, "LANG": "C.UTF-8"}


def _oneshot(args: list[str], cpu_sec: int, timeout: float) -> tuple[int, str, str]:
    tmp = tempfile.mkdtemp(prefix="aegis-l1-")
    try:
        cp = subprocess.run([sys.executable, "-m", "app.sandbox_child", *args], cwd=tmp, env=_env(tmp, "L1"),
                            capture_output=True, text=True, timeout=timeout, preexec_fn=_limits(cpu_sec))
        return cp.returncode, cp.stdout, cp.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)               # 회수 — 임시 FS 폐기


@lru_cache(maxsize=1)
def capabilities() -> dict:
    """커널이 실제로 주는 잠금 수단을 하위 프로세스로 확인 (프로세스당 1회)."""
    try:
        rc, out, err = _oneshot(["caps"], 10, 20)
        caps = json.loads(out.strip().splitlines()[-1]) if rc == 0 and out.strip() else {"error": (err or out)[-200:]}
    except Exception as exc:  # noqa: BLE001
        caps = {"error": f"{type(exc).__name__}: {exc}"}
    caps["rlimits"] = {"cpuSec": settings.sandbox_cpu_sec, "memoryMB": MEM_BYTES // 2**20, "nofile": 64, "fsizeMB": 16}
    return caps


def available(level: str) -> bool:
    if level == "L0":
        return True
    if level == "L1":
        return bool(capabilities().get("seccomp"))
    if level == "L2":
        return bool((l2_health() or {}).get("ready"))
    return False                                              # L3 런타임 없음 (KVM 없음)


def max_level() -> str:
    return next(lv for lv in ("L2", "L1", "L0") if available(lv))


# ── L2 브로커 (gVisor, Epic 65) ──────────────────────────────
L2_TTL = 15.0
_l2: dict = {"at": 0.0, "health": None}


def _l2_call(method: str, path: str, body: dict | None = None, timeout: float = 5.0) -> tuple[int, dict]:
    import urllib.error
    import urllib.request
    from app import tls
    url = settings.sandbox_l2_url.rstrip("/") + path
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=tls.client_context() if url.startswith("https") else None) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {"error": str(exc)}


def l2_health(force: bool = False) -> dict | None:
    """브로커 준비 상태(15초 캐시). SANDBOX_L2_URL 이 비면 None = L2 없음."""
    if not settings.sandbox_l2_url:
        return None
    now = time.time()
    if force or now - _l2["at"] > L2_TTL:
        try:
            code, h = _l2_call("GET", "/health", timeout=3)
        except OSError as exc:
            code, h = 0, {"ready": False, "error": f"{type(exc).__name__}: {exc}"}
        _l2.update(at=now, health=h | {"reachable": code != 0})
    return _l2["health"]


def _bundle(path: str | Path) -> str:
    from app.review import registry_dir
    return str(Path(path).resolve().relative_to(registry_dir().resolve()))


def decide_l2(path: str, req: JudgeRequest, engine: str, timeout: float) -> Decision:
    """L2 샌드박스 임대(브로커) → 판정 1건. 브로커 없음·고갈·시간 초과는 예외 → Agent.judge 가 failMode 로 강등(등급은 그대로)."""
    if not available("L2"):
        raise SandboxUnavailable("L2 격리 실행 환경 없음 — 격리 강등 금지(§8.6)")
    _bump("L2", "active")
    try:
        try:
            code, msg = _l2_call("POST", "/decide", {"bundle": _bundle(path), "engine": engine, "timeout": timeout,
                                                      "req": req.model_dump(by_alias=True, mode="json")}, timeout=timeout + 1)
        except OSError as exc:
            _bump("L2", "errors")
            raise RuntimeError(f"L2 브로커 연결 실패: {exc}") from exc
        if code == 503:
            _bump("L2", "rejected")
            raise SandboxBusy(msg.get("error") or "L2 풀 고갈")
        if code == 504:
            _bump("L2", "timeouts")
            raise TimeoutError(msg.get("error") or "L2 응답 시간 초과")
        if code != 200 or "error" in msg:
            _bump("L2", "errors")
            raise RuntimeError(msg.get("error") or f"L2 브로커 {code}")
        _bump("L2", "served")
        return Decision.model_validate(msg["decision"])
    finally:
        _bump("L2", "active", -1)


# ── L1 웜 슬롯 ───────────────────────────────────────────────
@dataclass
class _Worker:
    path: str
    proc: subprocess.Popen
    tmp: str
    lock: threading.Lock = field(default_factory=threading.Lock)
    uses: int = 0
    started: float = field(default_factory=time.time)
    caps: dict = field(default_factory=dict)

    def kill(self) -> None:
        try:
            self.proc.kill()
            self.proc.wait(timeout=2)
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)


_workers: dict[str, _Worker] = {}


def _readline(w: _Worker, timeout: float) -> dict:
    r, _, _ = select.select([w.proc.stdout], [], [], timeout)
    if not r:
        raise TimeoutError(f"L1 응답 {timeout:.2f}s 초과")
    line = w.proc.stdout.readline()
    if not line:
        raise RuntimeError(f"L1 하위 프로세스 종료 (code {w.proc.poll()})")
    return json.loads(line)


def _spawn(path: str) -> _Worker:
    tmp = tempfile.mkdtemp(prefix="aegis-l1-")
    proc = subprocess.Popen([sys.executable, "-m", "app.sandbox_child", "serve", path], cwd=tmp, env=_env(tmp, "L1"),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            bufsize=1, preexec_fn=_limits(settings.sandbox_cpu_sec))
    w = _Worker(path=path, proc=proc, tmp=tmp)
    try:
        hello = _readline(w, 15)
    except Exception:
        w.kill()
        raise
    if not hello.get("ready"):
        w.kill()
        raise RuntimeError(f"L1 기동 실패: {hello}")
    w.caps = hello.get("caps", {})
    _bump("L1", "spawned")
    return w


def _recycle(w: _Worker) -> None:
    with _lock:
        if _workers.get(w.path) is w:
            del _workers[w.path]
    w.kill()
    _bump("L1", "recycled")


def decide(path: str, req: JudgeRequest, engine: str, timeout: float) -> Decision:
    """L1 슬롯 임대 → 판정 1건 → 반납(사용 횟수 초과·오류·시간 초과면 회수)."""
    if not available("L1"):
        raise SandboxUnavailable("L1 격리 실행 환경 없음 — 격리 강등 금지(§8.6)")
    _bump("L1", "queued")
    got = _sem.acquire(timeout=settings.sandbox_queue_sec)
    _bump("L1", "queued", -1)
    if not got:
        _bump("L1", "rejected")
        raise SandboxBusy(f"L1 풀 고갈 — 대기 {settings.sandbox_queue_sec}s 후 거부 (격리 강등 금지)")
    _bump("L1", "active")
    try:
        with _lock:
            w = _workers.get(path)
        if w is None or w.proc.poll() is not None:
            w = _spawn(path)
            with _lock:
                _workers[path] = w
        with w.lock:
            w.proc.stdin.write(json.dumps({"req": req.model_dump(by_alias=True, mode="json"), "engine": engine}) + "\n")
            w.proc.stdin.flush()
            try:
                msg = _readline(w, timeout)
            except TimeoutError:
                _bump("L1", "timeouts")
                _recycle(w)
                raise
            except Exception:
                _bump("L1", "errors")
                _recycle(w)
                raise
            w.uses += 1
        if w.uses >= settings.sandbox_recycle_uses:
            _recycle(w)
        if "error" in msg:
            _bump("L1", "errors")
            raise RuntimeError(msg["error"])
        _bump("L1", "served")
        return Decision.model_validate(msg["decision"])
    finally:
        _bump("L1", "active", -1)
        _sem.release()


def warm(path: Path, level: str = "L1") -> None:
    """활성화 직후 L1 하위 프로세스(L2 는 브로커 샌드박스)를 미리 띄운다(첫 판정이 기동 시간으로 강등되지 않게). 백그라운드."""
    def run():
        try:
            if level == "L2":
                if available("L2"):
                    _l2_call("POST", "/warm", {"bundle": _bundle(path)}, timeout=60)
                return
            with _lock:
                exists = str(path) in _workers
            if not exists and available("L1"):
                w = _spawn(str(path))
                with _lock:
                    _workers[str(path)] = w
        except Exception:  # noqa: BLE001 — 실패하면 첫 요청이 다시 띄운다
            pass
    threading.Thread(target=run, daemon=True).start()


def retire(agent_root: Path) -> None:
    """새 버전 활성화 시 이전 버전 하위 프로세스(L2 는 브로커 샌드박스) 회수."""
    if available("L2"):
        try:
            _l2_call("POST", "/retire", {"agent": agent_root.name}, timeout=10)
        except OSError:
            pass
    with _lock:
        old = [w for p, w in _workers.items() if Path(p).parent == agent_root]
    for w in old:
        _recycle(w)


def sandboxed_agent(path: Path, m: Manifest | None = None) -> Agent:
    """L1·L2 에이전트 대리 — 부모는 매니페스트만 읽고 코드는 격리 안에서만 적재·실행한다.
    Agent.judge 의 검증(DP3 근거·매니페스트 판정 유형)·강등(failMode)을 그대로 쓴다."""
    m = m or load_manifest(path / "agent.yaml")
    from app import orchestrator
    timeout = orchestrator.timeout_s(m.spec.gate) or settings.sandbox_call_timeout_sec
    run = decide_l2 if m.spec.isolation == "L2" else decide

    def detect(req: JudgeRequest, eng: EngineAdapter) -> Decision:
        return run(str(path), req, eng.id, timeout)
    engines = {e.id: EngineAdapter(e.id, None) for e in m.spec.engines.available if e.kind == "builtin"}
    return Agent(manifest=m, path=path, detect=detect, engines=engines, rules={})


def replay(path: Path, level: str = "L1") -> tuple[int, str, str]:
    """등록 심사 R4 — L1(또는 L2 브로커) 안에서 골든·공격 재생 (일회성 발급·회수)."""
    if level == "L2":
        code, msg = _l2_call("POST", "/replay", {"bundle": _bundle(path), "cpuSec": settings.review_cpu_sec},
                             timeout=settings.review_cpu_sec * 3 + 15)
        return (0, json.dumps(msg), "") if code == 200 else (1, "", msg.get("error") or f"L2 브로커 {code}")
    _bump("L1", "spawned")
    try:
        return _oneshot(["replay", str(path)], settings.review_cpu_sec, settings.review_cpu_sec * 3)
    finally:
        _bump("L1", "recycled")


def probe(level: str = "L1") -> dict:
    if level == "L2":
        if not available("L2"):
            return {"ok": False, "level": "L2", "error": "L2 격리 실행 환경 없음", "results": []}
        code, msg = _l2_call("POST", "/probe", {}, timeout=150)
        if code != 200:
            return {"ok": False, "level": "L2", "error": msg.get("error"), "results": []}
        return msg | {"level": "L2", "results": msg["boundary"]["results"] + msg["inner"]["results"], "caps": msg["inner"].get("caps")}
    rc, out, err = _oneshot(["probe"], 10, 30)
    if rc != 0 or not out.strip():
        return {"ok": False, "error": (err or out)[-300:], "results": []}
    d = json.loads(out.strip().splitlines()[-1])
    d["ok"] = all(r["blocked"] for r in d["results"]) and d["control"]["tmpWrite"]
    return d


def status() -> dict:
    caps = capabilities()
    with _lock:
        workers = [{"agent": Path(w.path).parent.name if w.path.endswith("current") else Path(w.path).name,
                    "pid": w.proc.pid, "uses": w.uses, "startedAt": w.started, "alive": w.proc.poll() is None}
                   for w in _workers.values()]
        stats = {k: dict(v) for k, v in STATS.items()}
    l2 = l2_health(force=True)                      # 브로커 통계는 화면을 열 때마다 새로
    pools = []
    for lv in LEVELS:
        ok = available(lv)
        pool = {"level": lv, "mechanism": MECHANISM[lv], "available": ok,
                "capacity": None if lv == "L0" else settings.sandbox_l1_slots if lv == "L1" else (l2 or {}).get("slots", 0) if lv == "L2" else 0,
                "status": "사용 가능" if ok else "런타임 없음 — 해당 등급 에이전트는 보류(격리 강등 금지)", **stats[lv]}
        if lv == "L2" and l2:
            pool |= {"runtime": l2.get("runsc"), "kernel": l2.get("kernel"), "coldStartMs": l2.get("coldStartMs"),
                     "broker": l2.get("stats"), "sandboxes": len(l2.get("sandboxes") or []), "error": l2.get("error")}
        pools.append(pool)
    return {"maxLevel": max_level(), "pools": pools, "workers": workers, "capabilities": caps,
            "policy": "요청 단위 발급·회수 · 풀 고갈 시 대기 후 거부 · 격리 등급을 낮추지 않는다(§8.6)",
            "recycleUses": settings.sandbox_recycle_uses, "queueSec": settings.sandbox_queue_sec}


def shutdown() -> None:
    with _lock:
        ws = list(_workers.values())
        _workers.clear()
    for w in ws:
        w.kill()
