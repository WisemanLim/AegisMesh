"""Epic 18 — 폐쇄망 번들·신뢰 저장소·장터 (FR-P14, NFR-C3, SCR-A05·R05·C10)."""
import base64
import io
import json
import subprocess
import sys
import tarfile
from importlib import metadata

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete

from aegis import airgap
from aegis.agent import ROOT
from aegis.ledger_verify import canonical
from app import db, models, registry, sandbox

REL = Ed25519PrivateKey.generate()                         # 제품 릴리스 서명 키 (내부 신뢰 저장소)
PUBK = Ed25519PrivateKey.generate()                        # 서드파티 게시자 키
SRC = ROOT / "agents" / "d2-03-api-key-leaks"


def b64pub(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def agent_bundle(version="1.0.0", kid="pub-mkt", key=PUBK) -> dict:
    files = {str(p.relative_to(SRC)): p.read_text(encoding="utf-8").replace("D2-03", "X10") for p in sorted(SRC.rglob("*"))
             if p.is_file() and p.name != "agent.yaml" and "__pycache__" not in p.parts}
    m = yaml.safe_load((SRC / "agent.yaml").read_text())
    m["metadata"].update(id="x10", name="Partner Key Guard", nameKo="파트너 키 가드", version=version,
                         source={"diagram": "AegisMesh gap analysis", "domain": "X", "item": "Cost & service-level observability"})
    b = {"format": "aegismesh.io/AgentBundle/v1", "manifest": m, "files": files, "keyId": kid}
    b["signature"] = base64.b64encode(key.sign(canonical({"manifest": m, "files": files}))).decode()
    return b


def build(tmp_path, name="b.tar.gz", key=REL, kid="rel-2026", agents=(), vulndb=None, version="1.0.0") -> bytes:
    paths = []
    for i, b in enumerate(agents):
        p = tmp_path / f"ab{i}.json"
        p.write_text(json.dumps(b, ensure_ascii=False))
        paths.append(p)
    vp = None
    if vulndb:
        vp = tmp_path / "vulndb.json"
        vp.write_text(json.dumps(vulndb))
    out = tmp_path / name
    airgap.build(out, key, kid, version, True, paths, vp)
    return out.read_bytes()


def approve(client, as_user, aid):
    for who in ("ag.one", "ag.two"):
        r = client.post(f"/v1/approvals/{aid}:decide", json={"decision": "approve", "reason": "반입 승인"}, headers=as_user(who, "approver"))
    return r.json()


@pytest.fixture(scope="module")
def trusted(admin_headers):
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app, headers=admin_headers) as c:
        r = c.post("/v1/trust-keys", json={"keyId": "rel-2026", "name": "AegisMesh 릴리스 2026", "publicKey": b64pub(REL)})
        assert r.status_code in (202, 409)
        if r.status_code == 202:
            assert r.json()["status"] == "pending"
            aid = r.json()["approvalRef"]
            from conftest import _token                       # as_user 는 함수 범위 — 모듈 픽스처에서는 직접 발급
            for who in ("ag.one", "ag.two"):
                c.post(f"/v1/approvals/{aid}:decide", json={"decision": "approve", "reason": "릴리스 키"},
                       headers={"Authorization": f"Bearer {_token(who, ['approver'])}"})
        c.post("/v1/publishers", json={"keyId": "pub-mkt", "name": "Partner Sec", "publicKey": b64pub(PUBK), "tier": "partner"})
    return "rel-2026"


@pytest.fixture
def free_x10(client):
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
        s.execute(delete(models.MarketListing))
    registry.runtime_agent.cache_clear()
    yield
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
        registry.sync_builtin_agents(s)
    registry.runtime_agent.cache_clear()
    sandbox.shutdown()


def test_untrusted_key_rejected_until_two_person_approval(client, as_user, tmp_path):
    k = Ed25519PrivateKey.generate()
    r = client.post("/v1/trust-keys", json={"keyId": "rel-new", "name": "새 키", "publicKey": b64pub(k)})
    assert r.status_code == 202 and r.json()["status"] == "pending"
    data = build(tmp_path, key=k, kid="rel-new")
    rej = client.post("/v1/airgap/imports", content=data, headers={"content-type": "application/gzip"})
    assert rej.status_code == 422 and rej.json()["detail"]["steps"][0]["step"] == "signature"
    assert approve(client, as_user, r.json()["approvalRef"])["status"] == "approved"
    ok = client.post("/v1/airgap/imports", content=data, headers={"content-type": "application/gzip"}).json()
    assert ok["status"] == "imported" and [s["step"] for s in ok["steps"]] == ["signature", "hash", "sbom", "apply"]
    assert len(ok["applied"]["profiles"]) == 5
    rv = client.post("/v1/trust-keys/rel-new:revoke", json={"reason": "만료"}).json()
    approve(client, as_user, rv["approvalRef"])
    assert client.post("/v1/airgap/imports", content=data, headers={"content-type": "application/gzip"}).status_code == 422


def test_tamper_unknown_key_traversal_rejected(client, trusted, tmp_path):
    data = build(tmp_path)
    src = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as out:
        for m in src.getmembers():
            b = src.extractfile(m).read()
            if m.name == "profiles/chatbot-baseline.yaml":
                b = b.replace(b"enforce", b"observe")              # 구성요소 변조
            m.size = len(b)
            out.addfile(m, io.BytesIO(b))
    r = client.post("/v1/airgap/imports", content=buf.getvalue()).json()["detail"]
    assert [s["step"] for s in r["steps"]] == ["signature", "hash"] and not r["steps"][-1]["ok"]
    assert "chatbot-baseline" in r["steps"][-1]["detail"]
    bad = build(tmp_path, "u.tar.gz", key=Ed25519PrivateKey.generate(), kid="nobody")
    assert "신뢰 저장소에 없는 키" in client.post("/v1/airgap/imports", content=bad).json()["detail"]["steps"][0]["detail"]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as out:
        ti = tarfile.TarInfo("../escape.txt")
        ti.size = 1
        out.addfile(ti, io.BytesIO(b"x"))
    assert client.post("/v1/airgap/imports", content=buf.getvalue()).json()["detail"]["steps"][0]["step"] == "read"
    evs = [e["body"]["event"] for e in client.get("/v1/evidence", params={"kind": "airgap"}).json()["items"]]
    assert evs.count("bundle_rejected") >= 3


def test_sbom_vulnerability_gate(client, trusted, tmp_path):
    ver = metadata.version("PyYAML")
    db_ = {"version": "2099.01.01", "vulnerabilities": [{"id": "AEG-TEST-0001", "package": "pkg:pypi/pyyaml", "versions": [ver],
                                                          "severity": "critical", "summary": "시험용 합성 항목"}]}
    r = client.post("/v1/airgap/imports", content=build(tmp_path, vulndb=db_)).json()["detail"]
    assert r["steps"][-1]["step"] == "sbom" and "critical" in r["steps"][-1]["detail"] and r["steps"][0]["ok"]
    sb = client.get("/v1/sbom").json()
    names = {c["name"] for c in sb["sbom"]["components"]}
    assert sb["sbom"]["bomFormat"] == "CycloneDX" and "fastapi" in {n.lower() for n in names} and "aegismesh-agent-d1-05" in names
    assert sb["vulnGate"]["ok"]


def test_offline_cli_verify(client, trusted, tmp_path):
    build(tmp_path)
    (tmp_path / "trust.json").write_text(json.dumps(client.get("/v1/trust-keys:export").json()))
    ok = subprocess.run([sys.executable, "-m", "aegis", "airgap", "verify", str(tmp_path / "b.tar.gz"), "--trust", str(tmp_path / "trust.json")],
                        cwd=ROOT, capture_output=True, text=True)
    assert ok.returncode == 0 and "OK   signature" in ok.stdout and "OK   sbom" in ok.stdout, ok.stdout + ok.stderr
    (tmp_path / "trust.json").write_text(json.dumps({"keys": {}}))
    bad = subprocess.run([sys.executable, "-m", "aegis", "airgap", "verify", str(tmp_path / "b.tar.gz"), "--trust", str(tmp_path / "trust.json")],
                         cwd=ROOT, capture_output=True, text=True)
    assert bad.returncode == 1 and bad.stdout.startswith("FAIL signature")


def test_marketplace_install_and_rolling_update(client, as_user, trusted, tmp_path, free_x10):
    imp = client.post("/v1/airgap/imports", content=build(tmp_path, agents=[agent_bundle("1.0.0")])).json()
    assert imp["applied"]["listed"][0]["listing"] == "x10@1.0.0"
    lst = next(x for x in client.get("/v1/market").json()["items"] if x["id"] == "x10@1.0.0")
    assert lst["tier"] == "partner" and lst["status"] == "available" and lst["license"]
    ta = as_user("mk.admin", "tenant_admin", tenant="default")                               # 테넌트 관리자가 요청
    req = client.post("/v1/market/x10@1.0.0:request", json={}, headers=ta).json()
    assert req["status"] == "requested"
    assert client.get("/v1/agents/x10").status_code == 404                                    # 승인 전에는 설치 안 됨
    assert approve(client, as_user, req["approvalRef"])["status"] == "approved"
    assert next(x for x in client.get("/v1/market").json()["items"] if x["id"] == "x10@1.0.0")["status"] == "installed"
    a = client.get("/v1/agents/x10").json()
    assert a["origin"] == "api" and a["version"] == "1.0.0" and a["status"] == "alert_only"      # OQ2 — L3 없음: 경보 전용, 승격은 2인
    # 새 버전 반입 → 심사 후 롤링 교체 (재기동 없음)
    imp2 = client.post("/v1/airgap/imports", content=build(tmp_path, "b2.tar.gz", agents=[agent_bundle("1.1.0")], version="1.0.1")).json()
    assert imp2["applied"]["rolling"][0]["status"] == "installed"
    assert client.get("/v1/agents/x10").json()["version"] == "1.1.0"
    j = client.post("/v1/judge", params={"agent": "x10"}, json={"output": "AKIAIOSFODNN7EXAMPLE"}).json()
    assert j["verdict"] == "transform" and j["agent"]["version"] == "1.1.0"


def test_external_tier_cannot_install(client, trusted, tmp_path, free_x10):
    other = Ed25519PrivateKey.generate()
    client.post("/v1/airgap/imports", content=build(tmp_path, agents=[agent_bundle("2.0.0", "pub-unknown", other)]))
    lst = next(x for x in client.get("/v1/market").json()["items"] if x["id"] == "x10@2.0.0")
    assert lst["tier"] == "external"
    r = client.post("/v1/market/x10@2.0.0:request", json={})
    assert r.status_code == 403 and "external" in r.json()["detail"]
