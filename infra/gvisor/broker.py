"""L2 격리 브로커 (Epic 65 · FR-P08 · NFR-I) — 서드파티 에이전트 코드를 gVisor(사용자 공간 커널 Sentry, systrap)에서 실행한다.

샌드박스 1개 = `runsc do`: 루트 FS 는 /sandbox-rootfs(runtime 이미지 사본) 읽기 전용 + 1회용 tmpfs 덧씌움, 네트워크 없음,
에이전트 번들만 /agent 로. 안에서 `python -m app.sandbox_child serve /agent`(L1 과 같은 잠금 층·같은 JSON 줄 규약)가 돈다.
브로커 컨테이너는 비루트·능력 없음·읽기 전용이고, 브로커의 /tls·/registry 는 샌드박스에서 보이지 않는다.

  GET  /health                    준비 여부·runsc 판·슬롯·통계·웜 샌드박스
  POST /decide  {bundle, engine, req, timeout}   판정 1건(번들별 웜 샌드박스 임대 → 반납, 오류·시간 초과·사용 횟수 초과면 회수)
  POST /replay  {bundle, cpuSec}  등록 심사 R4 골든·공격 재생(1회용 샌드박스)
  POST /probe                     탈출 점검(gVisor 경계 + 안쪽 잠금 층)
  POST /warm    {bundle} · POST /retire {agent}

bundle = "<에이전트>/<판 디렉터리>" (REGISTRY 아래만). TLS_DIR 이 있으면 상호 TLS(클라이언트 인증서 필수).
"""
from __future__ import annotations

import json
import os
import re
import select
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REG = Path(os.environ.get("L2_REGISTRY", "/registry"))
ROOTFS = os.environ.get("L2_ROOTFS", "/sandbox-rootfs")
SLOTS = int(os.environ.get("L2_SLOTS", "4"))
QUEUE_SEC = float(os.environ.get("L2_QUEUE_SEC", "2"))
RECYCLE = int(os.environ.get("L2_RECYCLE_USES", "200"))
STATE = os.environ.get("L2_STATE", "/tmp/runsc")
BUNDLE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}/[A-Za-z0-9._-]{1,128}$")
ENV = {"PATH": "/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": "/app", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp",
       "SANDBOX_TMP": "/tmp", "AEGIS_RUNTIME_ISOLATION": "L2", "SANDBOX_SELF_RLIMIT": "1", "LANG": "C.UTF-8"}

_lock = threading.Lock()
_sem = threading.BoundedSemaphore(SLOTS)
STATS = {"served": 0, "rejected": 0, "timeouts": 0, "errors": 0, "spawned": 0, "recycled": 0, "active": 0}
INFO: dict = {"ready": False}


def _bump(k: str, n: int = 1) -> None:
    with _lock:
        STATS[k] += n


def runsc(*args: str, volume: str | None = None) -> list[str]:
    cmd = ["runsc", "--rootless", "--network=none", "--ignore-cgroups", f"--root={STATE}", "do", "-quiet", "-root", ROOTFS, "-cwd", "/tmp"]
    return cmd + (["-volume", f"{volume}:/agent"] if volume else []) + ["--", *args]


def bundle_dir(name: str) -> Path:
    if not isinstance(name, str) or not BUNDLE.match(name):
        raise ValueError("bundle 형식 오류")
    p = (REG / name).resolve()
    if REG.resolve() not in p.parents or not (p / "agent.yaml").is_file():
        raise ValueError("bundle 없음")
    return p


class Sandbox:
    def __init__(self, bundle: str):
        self.bundle, self.uses, self.started, self.lock = bundle, 0, time.time(), threading.Lock()
        self.proc = subprocess.Popen(runsc("python", "-m", "app.sandbox_child", "serve", "/agent", volume=str(bundle_dir(bundle))),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, env=ENV)
        hello = self.read(30)
        if not hello.get("ready"):
            self.kill()
            raise RuntimeError(f"L2 기동 실패: {hello}")
        self.caps = hello.get("caps", {})
        _bump("spawned")

    def read(self, timeout: float) -> dict:
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not r:
            raise TimeoutError(f"L2 응답 {timeout:.2f}s 초과")
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"L2 샌드박스 종료 (code {self.proc.poll()})")
        return json.loads(line)

    def kill(self) -> None:
        try:
            self.proc.kill()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass


_boxes: dict[str, Sandbox] = {}


def _recycle(b: Sandbox) -> None:
    with _lock:
        if _boxes.get(b.bundle) is b:
            del _boxes[b.bundle]
    b.kill()
    _bump("recycled")


def _box(bundle: str) -> Sandbox:
    with _lock:
        b = _boxes.get(bundle)
    if b is None or b.proc.poll() is not None:
        b = Sandbox(bundle)
        with _lock:
            _boxes[bundle] = b
    return b


def decide(body: dict) -> tuple[int, dict]:
    bundle_dir(body.get("bundle"))
    if not _sem.acquire(timeout=QUEUE_SEC):
        _bump("rejected")
        return 503, {"error": f"L2 풀 고갈 — 대기 {QUEUE_SEC}s 후 거부 (격리 강등 금지)"}
    _bump("active")
    try:
        b = _box(body["bundle"])
        with b.lock:
            b.proc.stdin.write(json.dumps({"req": body.get("req") or {}, "engine": body.get("engine")}) + "\n")
            b.proc.stdin.flush()
            try:
                msg = b.read(float(body.get("timeout") or 2.0))
            except TimeoutError as exc:
                _bump("timeouts")
                _recycle(b)
                return 504, {"error": str(exc)}
            except Exception as exc:  # noqa: BLE001
                _bump("errors")
                _recycle(b)
                return 502, {"error": f"{type(exc).__name__}: {exc}"[:300]}
            b.uses += 1
        if b.uses >= RECYCLE:
            _recycle(b)
        _bump("errors" if "error" in msg else "served")
        return 200, msg
    finally:
        _bump("active", -1)
        _sem.release()


def oneshot(args: list[str], timeout: float, volume: str | None = None) -> tuple[int, dict]:
    try:
        cp = subprocess.run(runsc(*args, volume=volume), capture_output=True, text=True, timeout=timeout, env=ENV)
    except subprocess.TimeoutExpired:
        return 504, {"error": f"벽시계 {timeout:.0f}s 초과로 강제 종료"}
    lines = cp.stdout.strip().splitlines()
    if cp.returncode != 0 or not lines:
        return 502, {"error": (cp.stderr or cp.stdout).strip()[-300:] or f"code {cp.returncode}", "code": cp.returncode}
    return 200, json.loads(lines[-1])


def probe() -> tuple[int, dict]:
    """gVisor 경계(잠금 층 없이) + 안쪽 잠금 층(L1 과 같은 점검). 덧씌움 쓰기는 샌드박스가 끝난 뒤 루트 FS 에 남았는지 본다."""
    marker = f"/app/l2-escape-{os.getpid()}-{int(time.time())}.txt"
    code, edge = oneshot(["python", "-m", "app.sandbox_child", "l2probe", marker], 60)
    if code != 200:
        return code, edge
    edge["results"].append({"test": f"루트 FS 쓰기({marker})가 샌드박스 밖에 남음", "blocked": not os.path.exists(ROOTFS + marker),
                            "layer": "gVisor 1회용 덧씌움", "detail": "샌드박스 종료 뒤 브로커에서 확인"})
    code, inner = oneshot(["python", "-m", "app.sandbox_child", "probe"], 60)
    if code != 200:
        return code, inner
    ok = all(r["blocked"] for r in edge["results"] + inner["results"]) and inner["control"]["tmpWrite"]
    return 200, {"ok": ok, "runsc": INFO.get("runsc"), "boundary": edge, "inner": inner}


def health() -> dict:
    with _lock:
        boxes = [{"bundle": b.bundle, "uses": b.uses, "startedAt": b.started, "alive": b.proc.poll() is None, "caps": b.caps}
                 for b in _boxes.values()]
        stats = dict(STATS)
    return INFO | {"slots": SLOTS, "queueSec": QUEUE_SEC, "recycleUses": RECYCLE, "stats": stats, "sandboxes": boxes}


def _startup() -> None:
    """runsc 판 + 실제 샌드박스 1회(커널 = gVisor 인지) — 성공해야 준비."""
    try:
        v = subprocess.run(["runsc", "--version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        t0 = time.perf_counter()
        cp = subprocess.run(runsc("python", "-c", "import platform; print(platform.release())"), capture_output=True, text=True,
                            timeout=60, env=ENV)
        kernel = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else ""
        INFO.update({"runsc": v, "kernel": kernel, "coldStartMs": round((time.perf_counter() - t0) * 1000), "platform": "systrap",
                     "ready": cp.returncode == 0 and "gvisor" in kernel, "error": None if "gvisor" in kernel else (cp.stderr or "")[-300:]})
    except Exception as exc:  # noqa: BLE001
        INFO.update({"ready": False, "error": f"{type(exc).__name__}: {exc}"})


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200 if self.path == "/health" and INFO.get("ready") else 503 if self.path == "/health" else 404, health())

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            if not INFO.get("ready"):
                return self._send(503, {"error": "L2 준비 안 됨", **INFO})
            if self.path == "/decide":
                return self._send(*decide(body))
            if self.path == "/replay":
                cpu = int(body.get("cpuSec") or 30)
                return self._send(*oneshot(["python", "-m", "app.sandbox_child", "replay", "/agent"], cpu * 3,
                                           volume=str(bundle_dir(body.get("bundle")))))
            if self.path == "/probe":
                return self._send(*probe())
            if self.path == "/warm":
                bundle_dir(body.get("bundle"))
                _box(body["bundle"])
                return self._send(200, {"warm": body.get("bundle")})
            if self.path == "/retire":
                agent = str(body.get("agent") or "")
                with _lock:
                    old = [b for k, b in _boxes.items() if k.split("/")[0] == agent]
                for b in old:
                    _recycle(b)
                return self._send(200, {"retired": len(old)})
            self._send(404, {"error": "없음"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"[:300]})

    def log_message(self, *_):
        pass


def main() -> None:
    os.makedirs(STATE, exist_ok=True)
    threading.Thread(target=_startup, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler)
    d = os.environ.get("TLS_DIR")
    if d:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(f"{d}/tls.crt", f"{d}/tls.key")
        ctx.load_verify_locations(f"{d}/ca.crt")
        ctx.verify_mode = ssl.CERT_REQUIRED
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"sandbox-l2 listening tls={bool(d)} slots={SLOTS}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
