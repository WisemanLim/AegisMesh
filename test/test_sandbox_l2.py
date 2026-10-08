"""Epic 65 — L2 격리(gVisor 브로커): 심사 R4 재생·판정이 브로커로만 가고, 브로커 없음·고갈은 강등(failMode)이지 등급 하향이 아님.

실제 gVisor(runsc) 경계·탈출 점검은 compose sandbox-l2 실측(test/impl/65th). 여기서는 같은 규약의 가짜 브로커(L1 로 대신 실행).
"""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.agent import ROOT
from aegis.schemas import JudgeRequest
from app import registry, sandbox
from app.core.config import settings
from app.review import registry_dir
from test.test_sandbox import bundle, free_x10  # noqa: F401 — 픽스처 재사용

CALLS: list[tuple[str, dict]] = []
MODE = {"busy": False}


class FakeBroker(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"ready": True, "runsc": "runsc version fake", "kernel": "4.19.0-gvisor", "slots": 2, "stats": {}, "sandboxes": []})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])) or b"{}")
        CALLS.append((self.path, body))
        if self.path == "/decide":
            if MODE["busy"]:
                return self._send(503, {"error": "L2 풀 고갈 — 대기 2s 후 거부 (격리 강등 금지)"})
            d = sandbox.decide(str(registry_dir() / body["bundle"]), JudgeRequest.model_validate(body["req"]), body["engine"], body["timeout"])
            return self._send(200, {"decision": d.model_dump(by_alias=True, mode="json")})
        if self.path == "/replay":
            rc, out, err = sandbox.replay(registry_dir() / body["bundle"])
            return self._send(200, json.loads(out.strip().splitlines()[-1])) if rc == 0 else self._send(502, {"error": err[-200:]})
        self._send(200, {})

    def log_message(self, *_):
        pass


@pytest.fixture
def broker(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeBroker)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(settings, "sandbox_l2_url", f"http://127.0.0.1:{srv.server_address[1]}")
    env = sandbox._env
    monkeypatch.setattr(sandbox, "_env", lambda tmp, level: env(tmp, "L2"))         # 가짜 브로커의 하위 프로세스 = 실제 브로커처럼 런타임 L2 표시
    sandbox._l2.update(at=0.0, health=None)
    CALLS.clear()
    MODE["busy"] = False
    yield srv
    srv.shutdown()
    sandbox._l2.update(at=0.0, health=None)


def test_l2_agent_reviewed_and_judged_only_through_broker(client, free_x10, broker):  # noqa: F811
    st = client.get("/v1/sandbox").json()
    assert st["maxLevel"] == "L2" and st["pools"][2]["available"] and st["pools"][2]["runtime"] == "runsc version fake"
    rv = client.post("/v1/agents", json=bundle("L2")).json()["review"]
    assert "L2 샌드박스(gVisor)" in rv["stages"]["R4"]["detail"] and rv["stages"]["R4"]["isolation"]["ran"] == "L2", rv
    assert rv["outcome"] == "alert_only"                                             # L3 없음 → 경보 전용(OQ2)
    replay = next(b for p, b in CALLS if p == "/replay")
    assert replay["bundle"].startswith("x10/") and ".." not in replay["bundle"]
    served = sandbox.STATS["L2"]["served"]
    j = client.post("/v1/judge", params={"agent": "x10"}, json={"output": "AKIAIOSFODNN7EXAMPLE"}).json()
    assert j["verdict"] == "transform" and j["ruleId"].startswith("X10.") and not j["degraded"]
    assert sandbox.STATS["L2"]["served"] == served + 1 and [p for p, _ in CALLS].count("/decide") == 1


def test_broker_busy_or_gone_degrades_never_downgrades(client, free_x10, broker):  # noqa: F811
    assert client.post("/v1/agents", json=bundle("L2")).status_code == 201
    agent = registry.runtime_agent("x10", "api")
    MODE["busy"] = True
    f = agent.judge(JudgeRequest(output="AKIAIOSFODNN7EXAMPLE"))
    assert f.degraded and "풀 고갈" in f.evidence[0].note
    l1 = sandbox.STATS["L1"]["served"]
    broker.shutdown()
    broker.server_close()
    sandbox._l2.update(at=0.0, health=None)
    f = agent.judge(JudgeRequest(output="AKIAIOSFODNN7EXAMPLE"))
    assert f.degraded and "L2 격리 실행 환경 없음" in f.evidence[0].note
    assert sandbox.STATS["L1"]["served"] == l1                                        # L1 로 대신 돌리지 않는다
    registry.runtime_agent.cache_clear()
    with pytest.raises(Exception, match="요구 격리 L2"):
        registry.runtime_agent("x10", "api")


def test_probe_level_and_broker_bundle_validation(client, tmp_path, monkeypatch):
    assert client.post("/v1/sandbox:probe", params={"level": "L3"}).status_code == 422
    assert client.post("/v1/sandbox:probe", params={"level": "L2"}).json() == {"ok": False, "level": "L2", "error": "L2 격리 실행 환경 없음", "results": []}
    spec = importlib.util.spec_from_file_location("l2broker", ROOT / "infra" / "gvisor" / "broker.py")
    br = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(br)
    monkeypatch.setattr(br, "REG", tmp_path)
    (tmp_path / "x10" / "abc").mkdir(parents=True)
    (tmp_path / "x10" / "abc" / "agent.yaml").write_text("x")
    assert br.bundle_dir("x10/abc") == (tmp_path / "x10" / "abc").resolve()
    for bad in ("../etc", "x10/../../etc", "/etc/passwd", "x10/abc/..", "x10/missing", None, "x10"):
        with pytest.raises(ValueError):
            br.bundle_dir(bad)
    cmd = br.runsc("python", "-c", "1", volume="/registry/x10/abc")
    assert "--network=none" in cmd and cmd[cmd.index("-root") + 1] == br.ROOTFS and "/registry/x10/abc:/agent" in cmd
