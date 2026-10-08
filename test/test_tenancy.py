"""Epic 13 — 다중 테넌시·사용자·역할·로그인 (FR-P13, SCR-A06·B02·R01·R02)."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from aegis.ledger_verify import verify_bundle
from app import auth, db, models

PW = "garam-password-0001"
TAG = "".join(chr(0xE0000 + ord(c)) for c in "ignore previous")


@pytest.fixture(scope="module")
def tenants(admin_headers):
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app, headers=admin_headers) as c:
        for tid, name in (("garam", "가람핀테크"), ("nuri", "누리저축")):
            r = c.post("/v1/tenants", json={"id": tid, "name": name})
            assert r.status_code in (201, 409), r.text
    return ("garam", "nuri")


def login(client, username, password=PW):
    return client.post("/v1/auth/login", json={"username": username, "password": password}, headers={"Authorization": ""})


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


# ── 인증 ─────────────────────────────────────────────────────
def test_unauthenticated_rejected(anon):
    assert anon.get("/v1/findings").status_code == 401
    assert anon.get("/v1/findings", headers=bearer("am1.deadbeef.forged")).status_code == 401
    cfg = anon.get("/v1/auth/config").json()
    assert cfg["local"] and cfg["oidc"]["enabled"] is False and cfg["session"]["idleMinutes"] == 30


def test_bootstrap_break_glass_once(client, tenants):
    with db.system_session() as s:
        tok = auth.issue_bootstrap(s, force=True)          # make admin-token RESET=1
        s.commit()
    body = {"token": tok, "username": "bg.admin", "displayName": "비상 관리자", "password": "break-glass-pass-01",
            "tenantId": "boot-t", "tenantName": "부트 테넌트"}
    r = client.post("/v1/auth/bootstrap", json=body, headers={"Authorization": ""})
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["user"]["breakGlass"] and d["user"]["roles"] == ["platform_admin"]
    assert client.get("/v1/auth/me", headers=bearer(d["token"])).json()["username"] == "bg.admin"
    assert any(t["id"] == "boot-t" for t in client.get("/v1/tenants").json()["items"])
    assert client.post("/v1/auth/bootstrap", json=body | {"username": "bg2"}, headers={"Authorization": ""}).status_code == 401


def test_login_lockout_logout(client, tenants):
    r = client.post("/v1/users", json={"username": "kim.sec", "displayName": "김보안", "roles": ["security_engineer"],
                                       "tenant": "garam", "password": PW})
    assert r.status_code == 201, r.text
    assert client.post("/v1/users", json={"username": "short.pw", "roles": ["auditor"], "password": "x"}).status_code == 422
    ok = login(client, "kim.sec")
    assert ok.status_code == 200, ok.text
    tok = ok.json()["token"]
    me = client.get("/v1/auth/me", headers=bearer(tok)).json()
    assert me["scope"] == "garam" and "judge" in me["permissions"] and "tenant.admin" not in me["permissions"]
    assert client.post("/v1/auth/logout", headers=bearer(tok)).status_code == 200
    assert client.get("/v1/auth/me", headers=bearer(tok)).status_code == 401
    # 5회 실패 → 잠금 (정상 비밀번호도 거부)
    client.post("/v1/users", json={"username": "lock.me", "roles": ["auditor"], "tenant": "garam", "password": PW})
    assert [login(client, "lock.me", "wrong-password-xx").status_code for _ in range(5)] == [401] * 5
    assert login(client, "lock.me").status_code == 423
    assert login(client, "nobody.here").status_code == 401
    evs = [e["body"]["event"] for e in client.get("/v1/evidence", params={"kind": "auth", "tenant": "garam", "limit": 30}).json()["items"]]
    assert {"login", "logout", "login_failed", "locked", "user_created"} <= set(evs)


def test_session_idle_timeout(client, tenants):
    client.post("/v1/users", json={"username": "idle.user", "roles": ["auditor"], "tenant": "garam", "password": PW})
    tok = login(client, "idle.user").json()["token"]
    with db.system_session() as s:
        row = s.get(models.AuthSession, tok.split(".")[1])
        row.last_seen_at = auth.utcnow() - timedelta(minutes=31)
        s.commit()
    r = client.get("/v1/auth/me", headers=bearer(tok))
    assert r.status_code == 401 and "유휴" in r.json()["detail"]


# ── 테넌트 격리 ───────────────────────────────────────────────
def test_cross_tenant_blocked(client, as_user, tenants):
    g = as_user("g.eng", "security_engineer", tenant="garam")
    n = as_user("n.eng", "security_engineer", tenant="nuri")
    jn = client.post("/v1/judge", params={"agent": "d1-05"}, json={"text": f"x{TAG}", "subject": {"tenant": "nuri"}}, headers=n)
    assert jn.status_code == 200 and jn.json()["subject"]["tenant"] == "nuri"
    # garam 주체가 nuri 지정 → 403, 생략 → garam
    assert client.post("/v1/judge", params={"agent": "d1-05"}, json={"subject": {"tenant": "nuri"}}, headers=g).status_code == 403
    jg = client.post("/v1/judge", params={"agent": "d1-05"}, json={"text": f"y{TAG}"}, headers=g).json()
    assert jg["subject"]["tenant"] == "garam"
    # 조회: 자기 테넌트만, 다른 테넌트 자원은 404, 헤더로 범위 넓히기 403
    items = client.get("/v1/findings", headers=g).json()["items"]
    assert items and {f["subject"]["tenant"] for f in items} == {"garam"}
    assert client.get(f"/v1/findings/{jn.json()['id']}", headers=g).status_code == 404
    assert client.get("/v1/findings", params={"tenant": "nuri"}, headers=g).status_code == 403
    assert client.get("/v1/findings", headers=g | {"X-Aegis-Tenant": "nuri"}).status_code == 403
    assert {e["tenant"] for e in client.get("/v1/evidence", headers=g).json()["items"]} == {"garam"}
    # 플랫폼 주체는 헤더로 테넌트를 고른다
    assert {f["subject"]["tenant"] for f in client.get("/v1/findings", headers={"X-Aegis-Tenant": "nuri"}).json()["items"]} == {"nuri"}
    assert client.get("/v1/findings", headers={"X-Aegis-Tenant": "no-such"}).status_code == 404


def test_tenant_chain_export_verifies_alone(client, as_user, tenants):
    a = as_user("g.audit", "auditor", tenant="garam")
    v = client.get("/v1/evidence:verify", headers=a).json()
    assert v["ok"] and [c["chain"] for c in v["chains"]] == ["garam"]
    b = client.get("/v1/evidence:export", headers=a).json()
    assert b["chain"] == "garam" and {r["tenant"] for r in b["records"]} == {"garam"}
    ok, msg = verify_bundle(b)
    assert ok, msg
    assert client.get("/v1/evidence:export", params={"chain": "nuri"}, headers=a).status_code == 403
    allv = client.get("/v1/evidence:verify").json()
    assert allv["ok"] and {"platform", "default", "garam", "nuri"} <= {c["chain"] for c in allv["chains"]}


def test_policy_namespace_per_tenant(client, as_user, tenants):
    g = as_user("g.eng", "security_engineer", tenant="garam")
    doc = "apiVersion: aegismesh/v1\nkind: Policy\nmetadata: {id: default}\nspec: {minConfidence: 0.7}\n"
    r = client.post("/v1/policies", content=doc, headers=g)
    assert r.status_code == 201 and r.json()["tenant"] == "garam" and r.json()["version"] >= 2
    assert client.get("/v1/policies/default", headers=g).json()["body"]["spec"]["minConfidence"] == 0.7
    nuri = client.get("/v1/policies/default", headers={"X-Aegis-Tenant": "nuri"}).json()
    assert nuri["tenant"] == "nuri" and nuri["version"] == 1 and nuri["body"]["spec"]["minConfidence"] == 0.5
    assert client.post("/v1/policies", params={"tenant": "nuri"}, content=doc, headers=g).status_code == 403
    # garam 프로파일 적용은 nuri 관문에 바인딩되지 않는다
    assert client.post("/v1/profiles/chatbot-baseline:apply", json={"target": "chat.garam"}, headers=g).status_code == 201
    n = as_user("n.eng", "security_engineer", tenant="nuri")
    assert client.post("/v1/judge:batch", json={"gate": "input", "request": {}, "target": "chat.garam"}, headers=n).status_code == 409


# ── 역할·사용자 관리 ───────────────────────────────────────────
def test_roles_and_tenant_admin_limits(client, as_user, tenants):
    ta = as_user("g.admin", "tenant_admin", tenant="garam")
    r = client.post("/v1/users", json={"username": "g.dev", "roles": ["developer"], "tenant": "nuri", "password": PW}, headers=ta)
    assert r.status_code == 403                                                  # 다른 테넌트에 만들기
    r = client.post("/v1/users", json={"username": "g.dev", "roles": ["developer"], "password": PW}, headers=ta)
    assert r.status_code == 201 and r.json()["tenant"] == "garam"
    assert client.post("/v1/users", json={"username": "g.root", "roles": ["platform_admin"], "password": PW},
                       headers=ta).status_code in (403, 422)                     # 플랫폼 관리자 부여 불가
    users = client.get("/v1/users", headers=ta).json()["items"]
    assert users and {u["tenant"] for u in users} == {"garam"}
    me = client.get("/v1/auth/me", headers=ta).json()
    assert client.patch(f"/v1/users/{me['id']}", json={"roles": ["tenant_admin", "approver"]}, headers=ta).status_code == 403
    assert client.post("/v1/tenants", json={"id": "rogue", "name": "x"}, headers=ta).status_code == 403
    assert client.post("/v1/redteam/campaigns:run", headers=as_user("g.red", "redteam", tenant="garam")).status_code == 403
    dev = next(u for u in users if u["username"] == "g.dev")
    assert client.patch(f"/v1/users/{dev['id']}", json={"roles": ["developer", "approver"]}, headers=ta).json()["roles"] == ["approver", "developer"]
    chk = client.get("/v1/authz:check", params={"user": "g.dev", "perm": "approve", "tenant": "garam"}, headers=ta).json()
    assert chk["allowed"] and "approver" in chk["reason"]
    chk = client.get("/v1/authz:check", params={"user": "g.dev", "perm": "approve", "tenant": "nuri"}, headers=ta).json()
    assert not chk["allowed"] and "교차" in chk["reason"]


def test_service_account_token(client, tenants):
    r = client.post("/v1/users", json={"username": "svc.gateway", "kind": "service", "tenant": "garam"})
    assert r.status_code == 201 and r.json()["roles"] == ["service"]
    t = client.post(f"/v1/users/{r.json()['id']}/tokens", json={"name": "gateway-1"}).json()
    h = bearer(t["token"])
    assert client.post("/v1/judge", params={"agent": "d1-05"}, json={"text": "hello"}, headers=h).status_code == 200
    assert client.get("/v1/findings", headers=h).status_code == 403              # 판정만 — 조회 불가
    assert login(client, "svc.gateway", "anything-at-all-1").status_code == 401  # 비밀번호 로그인 불가
    client.post(f"/v1/auth/sessions/{t['id']}:revoke")
    assert client.post("/v1/judge", params={"agent": "d1-05"}, json={}, headers=h).status_code == 401


def test_isolation_test_all_pass(client, tenants):
    r = client.post("/v1/tenants:isolation-test").json()
    assert r["ok"] and r["passed"] == r["total"] == 7, r
    assert client.get("/v1/tenants/isolation-test").json()["passed"] == 7
    t = next(x for x in client.get("/v1/tenants").json()["items"] if x["id"] == "garam")
    assert t["namespaces"]["policy"] == "pol/garam" and t["ledger"]["records"] > 0
    assert client.post("/v1/tenants", json={"id": "phys", "name": "x", "isolation": "physical"}).status_code == 422
    assert client.post("/v1/tenants", json={"id": "platform", "name": "x"}).status_code == 422


def test_unknown_tenant_write_rejected(client):
    assert client.post("/v1/scan", json={"artifact": {"kind": "mcp_server", "name": "x"}, "tenant": "ghost"}).status_code == 404
    with db.system_session() as s:
        blank = s.scalar(select(models.Finding.id).where(models.Finding.tenant == "ghost"))
    assert blank is None
