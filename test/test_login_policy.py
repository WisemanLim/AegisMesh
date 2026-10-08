"""Epic 38 — 로그인·등록 정책 (OQ3 결정): 특권 역할 2단계 강제(등록 전용 세션)·테넌트 전원 강제·인증기(AAGUID) 허용목록,
IdP 로그아웃 연동(Back-Channel·RP-Initiated)."""
import secrets
import time

from test_login_hardening import SoftAuthenticator, call, login
from test_sso import CLIENT, DOC, ISS, OTHER, idp, sign, sso_login  # noqa: F401 — idp 픽스처 재사용

from app.mfa import totp_code


def test_privileged_role_must_enroll_first(anon, as_user):
    as_user("pol.apr", "approver")
    r = login(anon, "pol.apr").json()
    assert r["enrollRequired"] is True
    tok = r["token"]
    blocked = call(anon, "GET", "/v1/approvals", tok)
    assert blocked.status_code == 401 and "mfa_enrollment_required" in blocked.text
    me = call(anon, "GET", "/v1/auth/me", tok).json()
    assert me["enrollRequired"] is True
    m = call(anon, "GET", "/v1/auth/mfa", tok).json()
    assert m["required"] is True and m["methods"] == [] and m["policy"]["mfa"] == "privileged"
    sec = call(anon, "POST", "/v1/auth/totp:setup", tok).json()["secret"]
    assert call(anon, "POST", "/v1/auth/totp:confirm", tok, json_={"code": totp_code(sec, int(time.time() // 30))}).status_code == 200
    assert call(anon, "GET", "/v1/approvals", tok).status_code == 200                       # 등록 즉시 세션 해제
    assert call(anon, "GET", "/v1/auth/me", tok).json()["enrollRequired"] is False
    assert "mfa" in login(anon, "pol.apr").json()                                            # 다음 로그인부터 2단계
    as_user("pol.eng", "security_engineer")
    assert login(anon, "pol.eng").json()["enrollRequired"] is False                          # 특권 아님 = 권장만


def test_tenant_policy_all_and_aaguid_allowlist(client, anon, as_user):
    client.post("/v1/tenants", json={"id": "polt", "name": "정책 시험"})
    assert client.put("/v1/tenants/polt/auth-policy", json={"mfa": "all", "aaguids": ["zz"]}).status_code == 422
    assert client.put("/v1/tenants/polt/auth-policy", json={"mfa": "all"}, headers=as_user("pol.dev", "developer")).status_code == 403
    assert client.put("/v1/tenants/polt/auth-policy", json={"mfa": "nobody"}).status_code == 422
    yubi = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
    p = client.put("/v1/tenants/polt/auth-policy", json={"mfa": "all", "aaguids": [yubi]}).json()
    assert p["mfa"] == "all" and p["aaguids"] == [yubi.replace("-", "")] and "approver" in p["privilegedRoles"]
    as_user("pol.t.eng", "security_engineer", tenant="polt")
    r = login(anon, "pol.t.eng").json()
    assert r["enrollRequired"] is True                                                       # 테넌트 전원 강제
    tok = r["token"]
    o = call(anon, "POST", "/v1/auth/webauthn/register:options", tok).json()
    assert o["publicKey"]["attestation"] == "direct" and o["aaguidAllowlist"] == [yubi.replace("-", "")]
    bad = call(anon, "POST", "/v1/auth/webauthn/register", tok, json_={"ticket": o["ticket"], "credential": SoftAuthenticator().create(o["publicKey"])})
    assert bad.status_code == 422 and "허용되지 않은 인증기" in bad.text                       # 소프트 인증기 AAGUID = 0
    assert call(anon, "GET", "/v1/auth/me", tok).json()["enrollRequired"] is True


def test_backchannel_and_rp_logout(anon, client, idp, monkeypatch):  # noqa: F811
    _, r = sso_login(anon, idp, sub="sub-bcl", user="sso.bcl")
    tok = r.json()["token"]
    assert call(anon, "GET", "/v1/auth/me", tok).status_code == 200
    now = time.time()
    base = {"iss": ISS, "aud": CLIENT, "iat": now, "sub": "sub-bcl", "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
    for over, key in (({"aud": "other"}, None), ({"nonce": "x"}, None), ({"events": {}}, None), ({}, OTHER)):
        bad = anon.post("/v1/auth/oidc/backchannel-logout", data={"logout_token": sign(base | over | {"jti": secrets.token_hex(8)}, **({"key": key} if key else {}))})
        assert bad.status_code == 400, (over, bad.text)
    assert call(anon, "GET", "/v1/auth/me", tok).status_code == 200                          # 거부된 토큰은 아무것도 폐기 안 함
    jti = secrets.token_hex(8)
    ok = anon.post("/v1/auth/oidc/backchannel-logout", data={"logout_token": sign(base | {"jti": jti})})
    assert ok.status_code == 200 and ok.json()["revoked"] >= 1 and ok.json()["user"] == "sso.bcl"
    assert call(anon, "GET", "/v1/auth/me", tok).status_code == 401
    assert anon.post("/v1/auth/oidc/backchannel-logout", data={"logout_token": sign(base | {"jti": jti})}).status_code == 400   # 재전송
    # RP-Initiated Logout — end_session_endpoint 가 있으면 콘솔 로그아웃이 IdP 로그아웃 주소를 돌려준다
    _, r = sso_login(anon, idp, sub="sub-bcl", user="sso.bcl")
    tok = r.json()["token"]
    monkeypatch.setitem(DOC, "end_session_endpoint", f"{ISS}/protocol/openid-connect/logout")
    from app import sso
    sso._cache.clear()
    out = call(anon, "POST", "/v1/auth/logout", tok, json_={"postLogoutRedirect": "http://console.test/login"}).json()
    assert out["idpLogout"].startswith(f"{ISS}/protocol/openid-connect/logout?client_id={CLIENT}") and "post_logout_redirect_uri=http%3A%2F%2Fconsole.test%2Flogin" in out["idpLogout"]
