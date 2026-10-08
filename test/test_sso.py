"""Epic 22 — 조직 SSO (OIDC 인가 코드 + PKCE, FR-D5-01·03, SCR-A06·B02). IdP 는 시험 안의 가짜(RS256 서명·PKCE 검사)."""
import base64
import hashlib
import json
import secrets
import time
import urllib.parse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import select

from app import auth, db, models, sso

ISS = "http://idp.test/realms/aegis"
CLIENT = "aegismesh-console"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
DOC = {"issuer": ISS, "authorization_endpoint": f"{ISS}/protocol/openid-connect/auth",
       "token_endpoint": f"{ISS}/protocol/openid-connect/token", "jwks_uri": f"{ISS}/protocol/openid-connect/certs",
       "code_challenge_methods_supported": ["plain", "S256"]}
REDIRECT = "http://console.test/auth/callback"
MAPS = [{"group": "sec-soc", "role": "security_engineer"}, {"group": "ciso-office", "role": "approver"},
        {"group": "tenant-admins", "role": "tenant_admin", "tenant": "default"}]


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def sign(claims: dict, key=KEY, kid="k1") -> str:
    h = b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    b = b64u(json.dumps(claims).encode())
    return f"{h}.{b}.{b64u(key.sign(f'{h}.{b}'.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


class FakeIdP:
    def __init__(self):
        self.codes: dict[str, tuple[str, str]] = {}
        self.posts: list[dict] = []

    def get(self, url):
        if url == f"{ISS}/.well-known/openid-configuration":
            return DOC
        n = KEY.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                          "n": b64u(n.n.to_bytes(256, "big")), "e": b64u(n.e.to_bytes(3, "big"))}]}

    def post(self, url, data):
        self.posts.append(data)
        id_token, challenge = self.codes.pop(data["code"])
        if b64u(hashlib.sha256(data["code_verifier"].encode()).digest()) != challenge:   # IdP 쪽 PKCE 검사
            raise sso.SsoError(401, "토큰 교환 실패: invalid_grant PKCE")
        return {"id_token": id_token, "access_token": "x", "token_type": "Bearer"}


@pytest.fixture
def idp(client, monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(sso, "_get_json", fake.get)
    monkeypatch.setattr(sso, "_post_form", fake.post)
    sso._cache.clear()
    assert client.put("/v1/auth/sso/mappings", json={"items": MAPS}).status_code == 200
    r = client.put("/v1/auth/sso", json={"issuer": ISS, "clientId": CLIENT, "enabled": True})
    assert r.status_code == 200 and r.json()["enabled"], r.text
    yield fake
    client.put("/v1/auth/sso", json={"issuer": ISS, "clientId": CLIENT, "enabled": False})
    client.put("/v1/auth/sso/mappings", json={"items": []})
    sso._cache.clear()


def sso_login(anon, fake, sub="sub-alice", user="sso.alice", groups=("sec-soc",), key=KEY, **over):
    r = anon.get("/v1/auth/oidc/start", params={"redirect": REDIRECT, "next": "/findings"})
    assert r.status_code == 200, r.text
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.json()["url"]).query))
    now = time.time()
    claims = {"iss": ISS, "aud": CLIENT, "azp": CLIENT, "sub": sub, "exp": now + 300, "iat": now, "nonce": q["nonce"],
              "preferred_username": user, "name": user.title(), "groups": list(groups), "acr": "mfa"} | over
    code = secrets.token_hex(8)
    fake.codes[code] = (sign(claims, key), q["code_challenge"])
    return q, anon.post("/v1/auth/oidc/callback", json={"code": code, "state": q["state"]})


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_disabled_until_configured(anon, client, monkeypatch):
    cfg = anon.get("/v1/auth/config").json()
    assert cfg["oidc"]["enabled"] is False and cfg["passwordLogin"] == "all"
    assert anon.get("/v1/auth/oidc/start", params={"redirect": REDIRECT}).status_code == 409
    fake = FakeIdP()
    monkeypatch.setattr(sso, "_get_json", fake.get)
    client.put("/v1/auth/sso/mappings", json={"items": []})
    r = client.put("/v1/auth/sso", json={"issuer": ISS, "clientId": CLIENT, "enabled": True})
    assert r.status_code == 422 and "매핑" in r.json()["detail"]                       # 매핑 없이 켜기 금지
    r = client.put("/v1/auth/sso", json={"issuer": "http://idp.test/realms/other", "clientId": CLIENT, "enabled": True})
    assert r.status_code == 502 and "issuer 불일치" in r.json()["detail"]
    assert client.put("/v1/auth/sso/mappings", json={"items": [{"group": "x", "role": "platform_admin", "tenant": "default"}]}).status_code == 422


def test_code_flow_pkce_mfa_and_group_roles(anon, idp):
    q, r = sso_login(anon, idp)
    assert q["response_type"] == "code" and q["code_challenge_method"] == "S256" and q["acr_values"] == "mfa"
    assert len(q["code_challenge"]) == 43 and q["redirect_uri"] == REDIRECT and "openid" in q["scope"]
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["next"] == "/findings" and body["user"]["username"] == "sso.alice"
    me = anon.get("/v1/auth/me", headers=bearer(body["token"])).json()
    assert me["roles"] == ["security_engineer"] and me["tenant"] is None
    sent = idp.posts[-1]
    assert sent["grant_type"] == "authorization_code" and sent["code_verifier"] and "client_secret" not in sent
    with db.system_session() as s:
        u = s.scalars(select(models.User).where(models.User.username == "sso.alice")).one()
        assert u.password_hash is None and u.external_id == f"{ISS}#sub-alice"
    again = anon.post("/v1/auth/oidc/callback", json={"code": "zzz", "state": q["state"]})
    assert again.status_code == 400                                                    # state 1회용
    q2, r2 = sso_login(anon, idp, acr="1", amr=["pwd", "otp"])                          # acr 대신 amr 의 OTP 로도 MFA 인정
    assert r2.status_code == 200


@pytest.mark.parametrize("over,status,word", [
    ({"acr": "1", "amr": ["pwd"]}, 403, "MFA"),
    ({"groups": ["nobody"]}, 403, "매핑되지 않음"),
    ({"aud": "other-client"}, 401, "aud"),
    ({"nonce": "replayed"}, 401, "nonce"),
    ({"exp": 1}, 401, "만료"),
    ({"iss": "http://evil.test"}, 401, "iss"),
])
def test_rejections_are_recorded(anon, client, idp, over, status, word):
    _, r = sso_login(anon, idp, sub="sub-rej", user="sso.rej", **over)
    assert r.status_code == status and word in r.json()["detail"], r.text
    if status == 403:
        evs = [e["body"] for e in client.get("/v1/evidence", params={"kind": "auth", "limit": 5}).json()["items"]]
        assert any(e.get("event") == "sso_denied" and word in e.get("reason", "") for e in evs)


def test_bad_signature_and_pkce_mismatch(anon, idp):
    _, r = sso_login(anon, idp, sub="sub-sig", user="sso.sig", key=OTHER)
    assert r.status_code == 401 and "서명" in r.json()["detail"]
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(
        anon.get("/v1/auth/oidc/start", params={"redirect": REDIRECT}).json()["url"]).query))
    idp.codes["c1"] = (sign({"iss": ISS}), "not-the-challenge")
    r = anon.post("/v1/auth/oidc/callback", json={"code": "c1", "state": q["state"]})
    assert r.status_code == 401 and "PKCE" in r.json()["detail"]
    assert anon.get("/v1/auth/oidc/start", params={"redirect": "http://evil.test/steal"}).status_code == 422


def test_roles_follow_idp_groups_and_unmapping_revokes(anon, client, idp):
    _, r = sso_login(anon, idp, sub="sub-bob", user="sso.bob", groups=["ciso-office"])
    tok = r.json()["token"]
    assert anon.get("/v1/auth/me", headers=bearer(tok)).json()["roles"] == ["approver"]
    _, r = sso_login(anon, idp, sub="sub-bob", user="sso.bob", groups=["tenant-admins"])
    me = anon.get("/v1/auth/me", headers=bearer(r.json()["token"])).json()
    assert me["roles"] == ["tenant_admin"] and me["tenant"] == "default"
    assert anon.get("/v1/auth/me", headers=bearer(tok)).status_code == 401              # 테넌트 변경 → 기존 세션 회수
    tok2 = r.json()["token"]
    _, r = sso_login(anon, idp, sub="sub-bob", user="sso.bob", groups=[])
    assert r.status_code == 403
    assert anon.get("/v1/auth/me", headers=bearer(tok2)).status_code == 401             # 매핑 해제 → 세션 회수
    evs = [e["body"].get("event") for e in client.get("/v1/evidence", params={"kind": "auth", "limit": 20}).json()["items"]]
    assert "sso_roles_synced" in evs


def test_local_username_collision_refused(anon, idp, admin_headers):
    _, r = sso_login(anon, idp, sub="sub-mallory", user="test.admin")
    assert r.status_code == 409 and "충돌" in r.json()["detail"]


def test_password_login_only_break_glass_with_reason(anon, client, idp):
    from conftest import _token
    _token("pw.local", ["security_engineer"])                                          # 일반 로컬 계정 (비밀번호 있음)
    with db.system_session() as s:
        if not s.scalars(select(models.User).where(models.User.username == "sso.glass")).first():
            auth.create_user(s, None, "sso.glass", "비상", ["platform_admin"], None, "pytest-password-0001", break_glass=True)
            s.commit()
    pw = "pytest-password-0001"
    assert anon.get("/v1/auth/config").json()["passwordLogin"] == "break_glass"
    r = anon.post("/v1/auth/login", json={"username": "pw.local", "password": pw, "reason": "점검 목적"})
    assert r.status_code == 403 and "break-glass" in r.json()["detail"]
    assert anon.post("/v1/auth/login", json={"username": "sso.glass", "password": pw}).status_code == 400
    r = anon.post("/v1/auth/login", json={"username": "sso.glass", "password": pw, "reason": "IdP 장애 대응"})
    assert r.status_code == 200
    evs = [e["body"] for e in client.get("/v1/evidence", params={"kind": "auth", "limit": 5}).json()["items"]]
    assert any(e.get("event") == "break_glass_login" and e["reason"] == "IdP 장애 대응" for e in evs)
    notes = client.get("/v1/notifications", params={"hours": 1}).json()["items"]
    assert any(n["kind"] == "비상 관리자" and n["severity"] == "critical" for n in notes)
    t = client.post("/v1/auth/sso:test").json()
    by = {c["id"]: c for c in t["checks"]}
    assert by["discovery"]["ok"] and by["keys"]["ok"] and by["pkce"]["ok"] and by["mappings"]["ok"] and by["password"]["ok"]


def test_sso_settings_platform_only(client, as_user):
    for role, tenant in (("tenant_admin", "default"), ("security_engineer", None)):
        h = as_user(f"sso.{role}", role, tenant=tenant)
        assert client.get("/v1/auth/sso", headers=h).status_code == 403
        assert client.put("/v1/auth/sso", headers=h, json={"issuer": ISS, "clientId": CLIENT}).status_code == 403
