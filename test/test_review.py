"""Epic 10 — 등록 심사 R1~R5: 서명 번들, 정적 심사, 하위 프로세스 재생(L0), 품질 판정 (PRD §11.3)."""
import base64
import copy
import json
import subprocess
import sys

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete

from aegis.agent import ROOT
from aegis.ledger_verify import canonical
from app import db, models, registry

KEY = Ed25519PrivateKey.generate()
PUB = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
OTHER = Ed25519PrivateKey.generate()
SRC = ROOT / "agents" / "d2-03-api-key-leaks"


def base_bundle() -> dict:
    """d2-03 코드를 서드파티 'X10' 에이전트로 재포장한 번들."""
    files = {str(p.relative_to(SRC)): p.read_text(encoding="utf-8") for p in sorted(SRC.rglob("*"))
             if p.is_file() and p.name != "agent.yaml" and "__pycache__" not in p.parts}
    m = yaml.safe_load((SRC / "agent.yaml").read_text())
    m["metadata"].update(id="x10", name="Third-party Cost Key Guard", nameKo="서드파티 키 가드", version="0.9.0",
                         source={"diagram": "AegisMesh gap analysis", "domain": "X", "item": "Cost & service-level observability"})
    for f in list(files):                                       # 규칙 ID 접두사도 X10 으로
        files[f] = files[f].replace("D2-03", "X10")
    return {"format": "aegismesh.io/AgentBundle/v1", "manifest": m, "files": files}


def sign(b: dict, key=KEY, kid="pub-acme") -> dict:
    b = copy.deepcopy(b)
    b["keyId"] = kid
    b["signature"] = base64.b64encode(key.sign(canonical({"manifest": b["manifest"], "files": b["files"]}))).decode()
    return b


@pytest.fixture
def free_x10(client):
    """x10 항목의 내장 에이전트를 잠시 비운다(있다면). 끝나면 api 행 제거 후 재동기화."""
    assert client.post("/v1/publishers", json={"keyId": "pub-acme", "name": "Acme Security", "publicKey": PUB}).status_code == 201
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
    registry.runtime_agent.cache_clear()
    yield
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
        registry.sync_builtin_agents(s)
    registry.runtime_agent.cache_clear()


def post(client, bundle):
    return client.post("/v1/agents", json=bundle)


def test_publisher_requires_principal_and_valid_key(client, anon, as_user):
    assert anon.post("/v1/publishers", json={"keyId": "k01", "name": "x", "publicKey": PUB}).status_code == 401
    assert client.post("/v1/publishers", json={"keyId": "k01", "name": "x", "publicKey": PUB},
                       headers=as_user("dev.kim", "developer")).status_code == 403          # 플랫폼 관리자만
    assert client.post("/v1/publishers", json={"keyId": "k01", "name": "x", "publicKey": "A" * 44}).status_code == 422


def test_signed_bundle_passes_all_stages_and_runs(client, free_x10, as_user):
    r = post(client, sign(base_bundle()))
    assert r.status_code == 201, r.text
    d = r.json()
    st = d["review"]["stages"]
    # OQ2 결정 — L3 없는 설치: R4 는 L1 대체(격리 미달 표시), 품질을 통과해도 경보 전용, 차단 승격은 2인 승인
    assert d["review"]["outcome"] == "alert_only" and d["status"] == "alert_only" and d["origin"] == "api"
    assert [st[k]["result"] for k in ("R1", "R2", "R3", "R4", "R5", "R6")] == ["passed"] * 5 + ["published"]
    assert "L1 샌드박스" in st["R4"]["detail"] and "L1 대체" in st["R4"]["detail"] and st["R4"]["isolation"] == {"required": "L3", "ran": "L1", "shortfall": True}
    assert st["R5"]["metrics"]["detectionRate"] == 1.0 and "2인" in st["R5"]["promotion"]
    assert client.post("/v1/agents/x10:promote", json={"reason": "격리 미달 감수"}, headers=as_user("dev.p", "developer")).status_code == 403
    ap = client.post("/v1/agents/x10:promote", json={"reason": "골든·공격 L1 재생 통과 — 격리 미달 감수"}).json()
    for who in ("apr.p1", "apr.p2"):
        assert client.post(f"/v1/approvals/{ap['approvalRef']}:decide", json={"decision": "approve", "reason": "검토"},
                           headers=as_user(who, "approver")).status_code == 200
    assert client.get("/v1/agents/x10").json()["status"] == "active"
    assert client.post("/v1/agents/x10:promote", json={"reason": "다시 승격 요청"}).status_code == 409
    j = client.post("/v1/judge", params={"agent": "x10"}, json={"output": "AKIAIOSFODNN7EXAMPLE"}).json()
    assert j["verdict"] == "transform" and j["ruleId"].startswith("X10.")
    assert client.get("/v1/agents/x10/reviews").json()["items"][0]["outcome"] == "alert_only"


@pytest.mark.parametrize("mutate,needle", [
    (lambda b: sign(b) | {"files": {**b["files"], "core.py": b["files"]["core.py"] + "\n# tampered"}}, "서명 검증 실패"),
    (lambda b: b, "서명 없음"),
    (lambda b: sign(b, OTHER, "pub-unknown"), "신뢰하지 않는"),
    (lambda b: sign(b, OTHER, "pub-acme"), "서명 검증 실패"),
])
def test_r2_rejections(client, free_x10, mutate, needle):
    r = post(client, mutate(base_bundle()))
    assert r.status_code == 422 and needle in json.dumps(r.json(), ensure_ascii=False)
    assert r.json()["detail"]["review"]["outcome"] == "rejected"


def test_r1_rejects_builtin_item_and_bad_paths(client, free_x10):
    b = base_bundle()
    b["manifest"]["metadata"]["id"] = "d1-05"
    b["manifest"]["metadata"]["source"] = {"diagram": "Security Risks in AI Agents", "domain": "D1", "item": "Hidden payloads"}
    assert "내장 에이전트" in json.dumps(post(client, sign(b)).json(), ensure_ascii=False)
    b = base_bundle()
    b["files"]["../evil.py"] = "x = 1"
    assert "허용되지 않는 파일 경로" in json.dumps(post(client, sign(b)).json(), ensure_ascii=False)


@pytest.mark.parametrize("patch,needle", [
    (lambda b: b["files"].__setitem__("core.py", "import os\n" + b["files"]["core.py"]), "허용되지 않은 import os"),
    (lambda b: b["files"].__setitem__("core.py", b["files"]["core.py"] + "\nX = open('/etc/passwd').read()\n"), "금지 호출 open()"),
    (lambda b: b["files"].__setitem__("engines/secret_patterns.py", b["files"]["engines/secret_patterns.py"] + "\nY = ().__class__.__bases__\n"), "금지 속성"),
    (lambda b: b["manifest"]["spec"]["engines"]["available"].append({"id": "x", "kind": "external", "license": "BUSL-1.1"}), "BUSL"),
    (lambda b: b["files"].__setitem__("README.md", "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"), "자격증명"),
])
def test_r3_static_review_holds(client, free_x10, patch, needle):
    b = base_bundle()
    patch(b)
    d = post(client, sign(b)).json()
    assert d["review"]["outcome"] == "review_hold" and d["status"] == "review_hold"
    assert any(needle in i for i in d["review"]["stages"]["R3"]["issues"]), d["review"]["stages"]["R3"]
    assert client.post("/v1/judge", params={"agent": "x10"}, json={}).status_code == 409


def test_r4_holds_isolation_without_runtime(client, free_x10):
    b = base_bundle()
    b["manifest"]["spec"]["isolation"] = "L2"
    d = post(client, sign(b)).json()
    assert d["review"]["outcome"] == "review_hold" and "격리" in d["review"]["stages"]["R4"]["detail"]


def test_r5_quality_failure_is_alert_only(client, free_x10):
    b = base_bundle()
    b["files"]["tests/golden/extra.jsonl"] = "\n".join(
        json.dumps({"name": f"fp{i}", "request": {"output": f"postgresql://app:pw{i}x@db:5432/app"}}) for i in range(5)) + "\n"
    d = post(client, sign(b)).json()
    assert d["review"]["outcome"] == "alert_only" and d["status"] == "alert_only"
    assert "경보 전용" in d["review"]["stages"]["R5"]["detail"]


def test_cli_keygen_and_bundle(tmp_path):
    out = subprocess.run([sys.executable, "-m", "aegis", "keygen", "--out", str(tmp_path / "k")], cwd=ROOT,
                         capture_output=True, text=True, check=True)
    pub = json.loads(out.stdout)["publicKey"]
    out = subprocess.run([sys.executable, "-m", "aegis", "bundle", str(SRC), "--key", str(tmp_path / "k"), "--key-id", "k"],
                         cwd=ROOT, capture_output=True, text=True, check=True)
    b = json.loads(out.stdout)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(
        base64.b64decode(b["signature"]), canonical({"manifest": b["manifest"], "files": b["files"]}))
    assert "core.py" in b["files"] and b["manifest"]["metadata"]["id"] == "d2-03"


@pytest.mark.parametrize("patch,needle", [
    (lambda c: c.replace("def detect(req, engine):", "def detect(req, engine):\n    raise ValueError('boom')"), "예외"),
    (lambda c: c.replace("def detect(req, engine):", "def detect(req, engine):\n    x = 'a' * (2 ** 31)"), "예외"),
    (lambda c: c.replace("def detect(req, engine):", "def detect(req, engine):\n    while True:\n        pass"), "자원 한도"),
])
def test_r4_holds_crashing_or_runaway_code(client, free_x10, patch, needle):
    b = base_bundle()
    b["files"]["core.py"] = patch(b["files"]["core.py"])
    d = post(client, sign(b)).json()
    assert d["review"]["outcome"] == "review_hold" and needle in d["review"]["stages"]["R4"]["detail"], d["review"]["stages"]
