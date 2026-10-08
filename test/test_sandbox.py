"""Epic 17 — 샌드박스 브로커 (FR-P08, NFR-I, SCR-R04): L1 격리(Landlock·seccomp·rlimit) 요청 단위 발급·회수."""
import base64
import shutil
import threading

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete

from aegis.agent import ROOT
from aegis.ledger_verify import canonical
from aegis.schemas import JudgeRequest
from app import db, models, registry, sandbox
from app.core.config import settings

KEY = Ed25519PrivateKey.generate()
PUB = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
SRC = ROOT / "agents" / "d2-03-api-key-leaks"


def bundle(isolation="L1") -> dict:
    files = {str(p.relative_to(SRC)): p.read_text(encoding="utf-8").replace("D2-03", "X10") for p in sorted(SRC.rglob("*"))
             if p.is_file() and p.name != "agent.yaml" and "__pycache__" not in p.parts}
    m = yaml.safe_load((SRC / "agent.yaml").read_text())
    m["metadata"].update(id="x10", name="Sandboxed Key Guard", nameKo="샌드박스 키 가드", version="1.0.0",
                         source={"diagram": "AegisMesh gap analysis", "domain": "X", "item": "Cost & service-level observability"})
    m["spec"]["isolation"] = isolation
    b = {"format": "aegismesh.io/AgentBundle/v1", "manifest": m, "files": files, "keyId": "pub-sbx"}
    b["signature"] = base64.b64encode(KEY.sign(canonical({"manifest": b["manifest"], "files": b["files"]}))).decode()
    return b


@pytest.fixture
def free_x10(client):
    assert client.post("/v1/publishers", json={"keyId": "pub-sbx", "name": "Sandbox Test", "publicKey": PUB}).status_code == 201
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
    registry.runtime_agent.cache_clear()
    yield
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
        registry.sync_builtin_agents(s)
    registry.runtime_agent.cache_clear()
    sandbox.shutdown()


@pytest.fixture
def crafted(tmp_path):
    """잠금 우회를 시도하는 L1 에이전트 디렉터리 (등록 심사 R3 를 거치지 않은 코드로 샌드박스 층만 시험)."""
    def make(body: str):
        d = tmp_path / "evil"
        shutil.copytree(SRC, d, ignore=shutil.ignore_patterns("__pycache__"))
        core = (d / "core.py").read_text()
        (d / "core.py").write_text(core.replace("def detect(req, engine):", f"def detect(req, engine):\n{body}"))
        m = yaml.safe_load((d / "agent.yaml").read_text())
        m["spec"]["isolation"] = "L1"
        (d / "agent.yaml").write_text(yaml.safe_dump(m, allow_unicode=True))
        return d
    yield make
    sandbox.shutdown()


def test_escape_probe_all_blocked(client):
    r = client.post("/v1/sandbox:probe").json()
    assert r["ok"] and r["control"]["tmpWrite"], r
    assert r["caps"]["landlock"] >= 1 and "socket" in r["caps"]["seccomp"] and "execve" in r["caps"]["seccomp"]
    by = {x["test"]: x for x in r["results"]}
    assert by["libc socket(AF_INET) 직접 호출"]["detail"] == "EPERM"                 # 커널(seccomp) 층
    assert by["libc open(/app/data/app.db) 직접 호출"]["detail"] == "EACCES"         # 커널(Landlock) 층
    assert all(x["blocked"] for x in r["results"])
    st = client.get("/v1/sandbox").json()
    assert st["maxLevel"] == "L1" and [p["available"] for p in st["pools"]] == [True, True, False, False]


def test_l1_third_party_agent_reviewed_and_run_in_sandbox(client, free_x10):
    r = client.post("/v1/agents", json=bundle("L1"))
    assert r.status_code == 201, r.text
    rv = r.json()["review"]
    assert rv["outcome"] == "alert_only" and "L1 샌드박스" in rv["stages"]["R4"]["detail"] and rv["stages"]["R4"]["isolation"]["shortfall"]   # OQ2
    before = sandbox.STATS["L1"]["served"]
    j = client.post("/v1/judge", params={"agent": "x10"}, json={"output": "AKIAIOSFODNN7EXAMPLE"}).json()
    assert j["verdict"] == "transform" and j["ruleId"].startswith("X10.") and not j["degraded"]
    assert j["agent"]["id"] == "x10" and j["standards"]                              # Finding 은 부모가 매니페스트로 구성
    assert sandbox.STATS["L1"]["served"] == before + 1
    assert any(w["alive"] for w in client.get("/v1/sandbox").json()["workers"])
    with db.system_session() as s, s.begin():                                     # 시드 재실행이 서드파티를 덮지 않는다
        registry.sync_builtin_agents(s)
    assert client.get("/v1/agents/x10").json()["origin"] == "api"


def test_l2_agent_held(client, free_x10):
    d = client.post("/v1/agents", json=bundle("L2")).json()          # 실행이 L2 를 요구 — 대체 없이 보류(OQ2 대체는 시험 환경만)
    assert d["review"]["outcome"] == "review_hold" and "L2 실행 환경 없음" in d["review"]["stages"]["R4"]["detail"]


@pytest.mark.parametrize("body,needle", [
    ("    import socket\n    socket.create_connection(('1.1.1.1', 443), timeout=1)", "sandbox L1"),
    ("    open('/app/data/stolen.txt', 'w').write('x')", "sandbox L1"),
    ("    __import__('subprocess').run(['id'])", "sandbox L1"),
])
def test_escape_in_detect_degrades_by_fail_mode(crafted, body, needle):
    agent = sandbox.sandboxed_agent(crafted(body))
    f = agent.judge(JudgeRequest(output="hello"))
    expect = "block" if agent.manifest.spec.fail_mode == "closed" else "allow"
    assert f.degraded and f.verdict == expect and needle in f.evidence[0].note, f.evidence[0].note    # 매니페스트 failMode


def test_timeout_recycles_worker(crafted):
    agent = sandbox.sandboxed_agent(crafted("    while True:\n        pass"))
    t0, r0 = sandbox.STATS["L1"]["timeouts"], sandbox.STATS["L1"]["recycled"]
    f = agent.judge(JudgeRequest(output="x"))
    assert f.degraded and "초과" in f.evidence[0].note
    assert sandbox.STATS["L1"]["timeouts"] == t0 + 1 and sandbox.STATS["L1"]["recycled"] >= r0 + 1


def test_pool_exhaustion_rejects_not_downgrades(crafted, monkeypatch):
    agent = sandbox.sandboxed_agent(crafted(""))
    monkeypatch.setattr(sandbox, "_sem", threading.BoundedSemaphore(1))
    monkeypatch.setattr(settings, "sandbox_queue_sec", 0.2)
    sandbox._sem.acquire()                                                         # 슬롯 하나를 점유
    try:
        f = agent.judge(JudgeRequest(output="x"))
    finally:
        sandbox._sem.release()
    assert f.degraded and "풀 고갈" in f.evidence[0].note
    assert not agent.judge(JudgeRequest(output="AKIAIOSFODNN7EXAMPLE")).degraded      # 슬롯이 나면 정상
