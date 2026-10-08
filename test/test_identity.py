"""Epic 16 — 워크로드 신원(SPIFFE JWT-SVID)·동적 시크릿 (FR-P07, SCR-R03)."""
import base64
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app import db, identity, models


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture(scope="module")
def tenant_idt(admin_headers):
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app, headers=admin_headers) as c:
        assert c.post("/v1/tenants", json={"id": "idt", "name": "신원 시험"}).status_code in (201, 409)
        assert c.post("/v1/tenants", json={"id": "idt-b", "name": "신원 시험 B"}).status_code in (201, 409)
    return "idt"


@pytest.fixture(scope="module")
def svc(admin_headers, tenant_idt):
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app, headers=admin_headers) as c:
        u = c.post("/v1/users", json={"username": "svc.idt", "kind": "service", "tenant": "idt"})
        uid = u.json()["id"] if u.status_code == 201 else next(x["id"] for x in c.get("/v1/users").json()["items"] if x["username"] == "svc.idt")
        tok = c.post(f"/v1/users/{uid}/tokens", json={"name": "bootstrap", "ttlDays": 1}).json()["token"]
    return tok


def test_jwks_public_and_status(anon, client):
    j = anon.get("/v1/identity/jwks").json()
    k = j["keys"][0]
    assert k["kty"] == "OKP" and k["crv"] == "Ed25519" and j["trust_domain"] == "aegismesh.local"
    r = client.post("/v1/identity:rotate", json={}).json()
    st = client.get("/v1/identity").json()
    assert st["counts"]["agent"] >= 80 and st["counts"]["platform"] == 4 and st["valid"] >= 84 and st["ttlSec"] == 3600
    assert any(i["spiffeId"] == "spiffe://aegismesh.local/agent/d1-05" for i in st["items"])
    assert r["rotated"] >= 0 and client.post("/v1/identity:rotate", json={}).json()["rotated"] == 0     # 50% 전에는 회전 없음


def test_service_svid_auth_and_verify(client, svc, anon):
    r = client.post("/v1/identity/svid", headers=bearer(svc)).json()
    assert r["spiffeId"] == "spiffe://aegismesh.local/tenant/idt/svc/svc.idt"
    tok = r["svid"]
    head, body, sig = tok.split(".")
    pub = base64.urlsafe_b64decode(anon.get("/v1/identity/jwks").json()["keys"][0]["x"] + "==")
    Ed25519PublicKey.from_public_bytes(pub).verify(base64.urlsafe_b64decode(sig + "=="), f"{head}.{body}".encode())  # 독립 검증
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    assert claims["exp"] - claims["iat"] == 3600 and claims["aud"] == ["aegismesh"]
    # SVID 로 판정 호출 (정적 API 키 없이), 조회 권한은 없음
    j = client.post("/v1/judge", params={"agent": "d1-05"}, json={"text": "hi"}, headers=bearer(tok))
    assert j.status_code == 200 and j.json()["subject"]["tenant"] == "idt"
    assert client.get("/v1/findings", headers=bearer(tok)).status_code == 403
    assert client.post("/v1/identity:verify", json={"token": tok}).json()["valid"]
    assert not client.post("/v1/identity:verify", json={"token": tok, "audience": "other"}).json()["valid"]
    bad = f"{head}.{body}.{sig[:-4]}AAAA"
    assert client.post("/v1/identity:verify", json={"token": bad}).json()["reason"] == "JWT-SVID 서명 불일치"
    assert client.post("/v1/judge", params={"agent": "d1-05"}, json={}, headers=bearer(bad)).status_code == 401
    assert client.post("/v1/identity/svid").status_code == 403                        # 사람 사용자는 SVID 를 받지 않는다


def test_agent_svid_not_api_principal(client):
    with db.system_session() as s:
        identity.sync(s)
        tok = identity.issue(s, s.get(models.WorkloadIdentity, "spiffe://aegismesh.local/agent/d1-05"))
        s.commit()
    assert client.get("/v1/auth/me", headers=bearer(tok)).status_code == 403


def test_leases_downscoped_short_revocable(client, as_user, tenant_idt, svc):
    eng = as_user("idt.eng", "security_engineer", tenant="idt")
    assert client.post("/v1/secrets/leases", json={"path": "db/x", "scopes": ["*"]}, headers=eng).status_code == 422
    r = client.post("/v1/secrets/leases", json={"path": "db/payments-ro", "scopes": ["db:read", "tool:search_docs"], "ttlSec": 7200},
                    headers=eng).json()
    secret, lid = r["secret"], r["id"]
    assert secret.startswith("aeg_dyn_") and r["path"] == "idt/db/payments-ro"
    with db.system_session() as s:
        row = s.get(models.SecretLease, lid)
        assert (row.expires_at - row.issued_at) <= timedelta(seconds=900)               # 최대 15분으로 절단
        assert row.secret_hash != secret and len(row.secret_hash) == 64             # 원문 미보관
    assert all("secret" not in x for x in client.get("/v1/secrets/leases", headers=eng).json()["items"])
    ok = client.post("/v1/secrets:introspect", json={"secret": secret, "scope": "db:read"}, headers=bearer(svc)).json()
    assert ok["active"] and ok["tenant"] == "idt"
    out = client.post("/v1/secrets:introspect", json={"secret": secret, "scope": "db:write"}, headers=bearer(svc)).json()
    assert not out["active"] and "범위 밖" in out["reason"]
    other = as_user("idtb.eng", "security_engineer", tenant="idt-b")
    assert client.post("/v1/secrets:introspect", json={"secret": secret}, headers=other).json()["reason"] == "알 수 없는 시크릿"
    assert client.post(f"/v1/secrets/leases/{lid}:revoke", headers=other).status_code == 404
    assert client.post(f"/v1/secrets/leases/{lid}:renew", json={"ttlSec": 60}, headers=eng).json()["renewals"] == 1
    assert client.post(f"/v1/secrets/leases/{lid}:revoke", headers=eng).json()["state"] == "revoked"
    assert client.post("/v1/secrets:introspect", json={"secret": secret}, headers=bearer(svc)).json()["reason"] == "revoked"
    evs = [e["body"]["event"] for e in client.get("/v1/evidence", params={"kind": "secret", "tenant": "idt"}).json()["items"] if e["refId"] == lid]
    assert evs == ["lease_revoked", "lease_renewed", "lease_issued"]


def test_force_rotation_invalidates_svids_and_leases(client, svc, as_user):
    tok = client.post("/v1/identity/svid", headers=bearer(svc)).json()["svid"]
    eng = as_user("idt.eng", "security_engineer", tenant="idt")
    secret = client.post("/v1/secrets/leases", json={"path": "api/partner", "scopes": ["api:call"]}, headers=eng).json()["secret"]
    import time
    time.sleep(1.1)                                                                     # iat 초 단위
    r = client.post("/v1/identity:rotate", json={"force": True}).json()
    assert r["force"] and r["invalidated"] >= 85 and r["leasesRevoked"] >= 1
    assert client.post("/v1/judge", params={"agent": "d1-05"}, json={}, headers=bearer(tok)).status_code == 401
    assert client.post("/v1/secrets:introspect", json={"secret": secret}, headers=bearer(svc)).json()["reason"] == "revoked"
    new = client.post("/v1/identity/svid", headers=bearer(svc)).json()["svid"]          # 다시 발급하면 동작
    assert client.post("/v1/judge", params={"agent": "d1-05"}, json={}, headers=bearer(new)).status_code == 200
    assert client.get("/v1/identity").json()["lastRotation"]["force"] is True


def test_static_credentials_flagged(client, as_user):
    r = client.post("/v1/users", json={"username": "svc.static", "kind": "service", "tenant": "idt"})
    uid = r.json()["id"]
    client.post(f"/v1/users/{uid}/tokens", json={"name": "forever"})
    items = client.get("/v1/identity/static-credentials").json()["items"]
    assert any(x["user"] == "svc.static" and x["expiresAt"] is None for x in items)
    assert client.get("/v1/identity", headers=as_user("idt.eng", "security_engineer", tenant="idt")).status_code == 403   # 플랫폼 전용
