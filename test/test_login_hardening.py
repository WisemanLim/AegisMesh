"""Epic 34 — 로그인 보안 강화 (SCR-B02 · FR-D5-01·03): 패스키(WebAuthn)·OTP 2단계, DPoP 세션 바인딩, 새 기기·위치 재인증, 탈취 토큰 재사용 대응.

소프트웨어 인증기(P-256)로 등록·인증 응답을 만들고(브라우저 가상 인증기 E2E 는 test/e2e/passkey_e2e.py), DPoP 증명은 ES256 으로 직접 서명한다."""
import base64
import hashlib
import json
import os
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import select

from app import db, models
from app.mfa import totp_code

PW = "pytest-password-0001"           # conftest 시험 사용자 비밀번호
ORIGIN, RP = "http://localhost:3000", "localhost"
CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"
IPAD = "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def cbor(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


class SoftAuthenticator:
    def __init__(self, origin=ORIGIN, rp=RP):
        self.key, self.cid, self.count, self.origin, self.rp = ec.generate_private_key(ec.SECP256R1()), os.urandom(16), 0, origin, rp

    def _cd(self, kind, challenge):
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": False}).encode()

    def create(self, pk):
        n = self.key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        ad = hashlib.sha256(self.rp.encode()).digest() + bytes([0x01 | 0x04 | 0x40]) + (0).to_bytes(4, "big") + bytes(16) \
            + len(self.cid).to_bytes(2, "big") + self.cid + cose
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(self._cd("webauthn.create", pk["challenge"])),
                             "attestationObject": b64u(cbor({"fmt": "none", "attStmt": {}, "authData": ad})), "transports": ["internal"]}}

    def get(self, pk, count=None):
        self.count = self.count + 1 if count is None else count
        cd = self._cd("webauthn.get", pk["challenge"])
        ad = hashlib.sha256(self.rp.encode()).digest() + bytes([0x01 | 0x04]) + self.count.to_bytes(4, "big")
        sig = self.key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig)}}


class DpopKey:
    def __init__(self):
        self.k = ec.generate_private_key(ec.SECP256R1())

    def jwk(self):
        n = self.k.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}

    def proof(self, method, path, token=None, jti=None, iat=None):
        h = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()}
        p = {"htm": method, "htu": f"http://testserver{path}", "iat": int(iat or time.time()), "jti": jti or secrets.token_hex(12)}
        if token:
            p["ath"] = b64u(hashlib.sha256(token.encode()).digest())
        signing = f"{b64u(json.dumps(h).encode())}.{b64u(json.dumps(p).encode())}"
        r, s = decode_dss_signature(self.k.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
        return f"{signing}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def client_hdr(ip="203.0.113.10", ua=CHROME):
    return {"X-Aegis-Client-IP": ip, "X-Aegis-Client-UA": ua, "User-Agent": "node"}


def login(anon, user, key=None, **kw):
    h = client_hdr(**kw) | ({"DPoP": key.proof("POST", "/v1/auth/login")} if key else {})
    return anon.post("/v1/auth/login", json={"username": user, "password": PW}, headers=h)


def call(anon, method, path, token, key=None, json_=None, hdr=None, **kw):
    h = {"Authorization": f"Bearer {token}"} | client_hdr(**kw) | (hdr or {})
    if key:
        h["DPoP"] = key.proof(method, path, token)
    return anon.request(method, path, headers=h, json=json_)


def test_passkey_register_login_clone(anon, as_user):
    as_user("mfa.pk", "security_engineer")
    tok = login(anon, "mfa.pk").json()["token"]
    a = SoftAuthenticator()
    o = call(anon, "POST", "/v1/auth/webauthn/register:options", tok).json()
    assert o["publicKey"]["rp"]["id"] == RP and o["publicKey"]["authenticatorSelection"]["userVerification"] == "required"
    evil = SoftAuthenticator(origin="https://evil.example")
    assert call(anon, "POST", "/v1/auth/webauthn/register", tok, json_={"ticket": o["ticket"], "credential": evil.create(o["publicKey"])}).status_code == 422
    o = call(anon, "POST", "/v1/auth/webauthn/register:options", tok).json()
    r = call(anon, "POST", "/v1/auth/webauthn/register", tok, json_={"ticket": o["ticket"], "credential": a.create(o["publicKey"]), "name": "laptop"})
    assert r.status_code == 201, r.text
    assert call(anon, "GET", "/v1/auth/mfa", tok).json()["methods"] == ["webauthn"]
    first = login(anon, "mfa.pk").json()
    assert "token" not in first and first["mfa"]["methods"] == ["webauthn"] and first["mfa"]["publicKey"]["allowCredentials"][0]["id"] == b64u(a.cid)
    ok = anon.post("/v1/auth/mfa:verify", json={"ticket": first["mfa"]["ticket"], "credential": a.get(first["mfa"]["publicKey"])}, headers=client_hdr())
    assert ok.status_code == 200 and ok.json()["mfa"] == "webauthn"
    assert anon.post("/v1/auth/mfa:verify", json={"ticket": first["mfa"]["ticket"], "credential": a.get(first["mfa"]["publicKey"])}).status_code == 401   # 대기표 1회
    m = login(anon, "mfa.pk").json()["mfa"]
    clone = anon.post("/v1/auth/mfa:verify", json={"ticket": m["ticket"], "credential": a.get(m["publicKey"], count=1)})
    assert clone.status_code == 401 and "복제" in clone.text                                          # 서명 카운터 역행
    m = login(anon, "mfa.pk").json()["mfa"]
    wrong = a.get({"challenge": b64u(os.urandom(32))})
    assert anon.post("/v1/auth/mfa:verify", json={"ticket": m["ticket"], "credential": wrong}).status_code == 401   # 다른 challenge
    for _ in range(3):                                                                                # 복제·challenge 실패 2회 + 3회 = 5회
        m = login(anon, "mfa.pk").json()["mfa"]
        anon.post("/v1/auth/mfa:verify", json={"ticket": m["ticket"], "code": "000000"})
    assert login(anon, "mfa.pk").status_code == 423                                                   # 5회 실패 → 잠금
    with db.system_session() as s:
        u = s.scalars(select(models.User).where(models.User.username == "mfa.pk")).first()
        u.locked_until, u.failed_logins = None, 0
        s.commit()


def test_totp_fallback(anon, as_user):
    as_user("mfa.otp", "security_engineer")
    tok = login(anon, "mfa.otp").json()["token"]
    sec = call(anon, "POST", "/v1/auth/totp:setup", tok).json()["secret"]
    step = int(time.time() // 30)
    assert call(anon, "POST", "/v1/auth/totp:confirm", tok, json_={"code": "123456" if totp_code(sec, step) != "123456" else "654321"}).status_code == 422
    assert call(anon, "POST", "/v1/auth/totp:confirm", tok, json_={"code": totp_code(sec, step)}).status_code == 200
    m = login(anon, "mfa.otp").json()["mfa"]
    assert m["methods"] == ["totp"]
    assert anon.post("/v1/auth/mfa:verify", json={"ticket": m["ticket"], "code": totp_code(sec, step)}).status_code == 401    # 같은 코드 재사용
    m = login(anon, "mfa.otp").json()["mfa"]
    r = anon.post("/v1/auth/mfa:verify", json={"ticket": m["ticket"], "code": totp_code(sec, step + 1)})
    assert r.status_code == 200 and r.json()["mfa"] == "totp"


def test_dpop_binding_and_token_replay(anon, as_user, client):
    as_user("mfa.dpop", "security_engineer")
    k1, k2 = DpopKey(), DpopKey()
    t1 = login(anon, "mfa.dpop", k1).json()
    assert t1["dpop"] is True
    tok = t1["token"]
    me = call(anon, "GET", "/v1/auth/me", tok, k1).json()
    assert me["binding"]["dpop"] is True and me["binding"]["device"] == "Chrome · macOS" and me["binding"]["location"] == "203.0.113.0/24"
    stale = {"DPoP": k1.proof("GET", "/v1/auth/me", tok, iat=time.time() - 600)}
    assert call(anon, "GET", "/v1/auth/me", tok, hdr=stale).status_code == 401                      # 시각 오차 = 거부(폐기 아님)
    bad_ath = {"DPoP": k1.proof("GET", "/v1/auth/me", "other-token")}
    assert call(anon, "GET", "/v1/auth/me", tok, hdr=bad_ath).status_code == 401
    assert call(anon, "GET", "/v1/auth/me", tok, k1).status_code == 200                             # 아직 살아 있다
    other = login(anon, "mfa.dpop", k2).json()["token"]                                              # 같은 사용자 다른 세션
    stolen = call(anon, "GET", "/v1/auth/me", tok)                                                   # 증명 없이 토큰만 = 탈취 재사용
    assert stolen.status_code == 401 and "세션 탈취" in stolen.text
    assert call(anon, "GET", "/v1/auth/me", tok, k1).status_code == 401
    assert call(anon, "GET", "/v1/auth/me", other, k2).status_code == 401                           # 사용자 세션 전체 폐기
    incs = client.get("/v1/incidents?limit=50").json()["items"]
    assert any("D5-03.token-replay" in (i.get("title") or "") or "D5-03.token-replay" in str(i.get("rules")) for i in incs)
    with db.system_session() as s:
        ev = s.scalars(select(models.Evidence).where(models.Evidence.kind == "auth").order_by(models.Evidence.seq.desc()).limit(20)).all()
        assert any(e.body.get("event") == "token_replay" and e.body.get("revoked", 0) >= 2 for e in ev)
    # 다른 키로 서명한 증명 · 같은 증명(jti) 재사용도 탈취
    t3 = login(anon, "mfa.dpop", k1).json()["token"]
    assert call(anon, "GET", "/v1/auth/me", t3, k2).status_code == 401
    t4 = login(anon, "mfa.dpop", k1).json()["token"]
    p = {"DPoP": k1.proof("GET", "/v1/auth/me", t4, jti="replayed-jti-0001")}
    assert call(anon, "GET", "/v1/auth/me", t4, hdr=p).status_code == 200
    r = call(anon, "GET", "/v1/auth/me", t4, hdr=p)
    assert r.status_code == 401 and "재사용" in r.text


def test_new_device_location_reauth(anon, as_user):
    as_user("mfa.loc", "security_engineer")
    k = DpopKey()
    tok = login(anon, "mfa.loc", k).json()["token"]
    assert call(anon, "GET", "/v1/policies", tok, k).status_code == 200
    moved = call(anon, "GET", "/v1/policies", tok, k, ip="198.51.100.7", ua=IPAD)
    assert moved.status_code == 401 and "reauth_required" in moved.text
    me = call(anon, "GET", "/v1/auth/me", tok, k, ip="198.51.100.7", ua=IPAD).json()
    assert me["reauthRequired"] and "iPadOS" in me["reviewReason"] and "198.51.100.0/24" in me["reviewReason"]
    ss = call(anon, "GET", "/v1/auth/sessions", tok, k, ip="198.51.100.7", ua=IPAD).json()["items"]
    assert next(x for x in ss if x["current"])["state"] == "review"
    assert call(anon, "POST", "/v1/auth/reauth", tok, k, json_={"password": "wrong-password"}, ip="198.51.100.7", ua=IPAD).status_code == 401
    ok = call(anon, "POST", "/v1/auth/reauth", tok, k, json_={"password": PW}, ip="198.51.100.7", ua=IPAD).json()
    assert ok["ok"] and ok["device"] == "Safari · iPadOS" and ok["location"] == "198.51.100.0/24"
    assert call(anon, "GET", "/v1/policies", tok, k, ip="198.51.100.7", ua=IPAD).status_code == 200
    with db.system_session() as s:
        fs = s.scalars(select(models.Finding).where(models.Finding.agent_id == "d5-03", models.Finding.rule_id == "D5-03.fingerprint-mismatch")).all()
        assert any(f.rule_id == "D5-03.fingerprint-mismatch" for f in fs)
    # 패스키 사용자는 비밀번호로 재인증할 수 없다
    a = SoftAuthenticator()
    o = call(anon, "POST", "/v1/auth/webauthn/register:options", tok, k, ip="198.51.100.7", ua=IPAD).json()
    call(anon, "POST", "/v1/auth/webauthn/register", tok, k, json_={"ticket": o["ticket"], "credential": a.create(o["publicKey"])}, ip="198.51.100.7", ua=IPAD)
    call(anon, "GET", "/v1/policies", tok, k, ip="192.0.2.44", ua=IPAD)
    assert call(anon, "POST", "/v1/auth/reauth", tok, k, json_={"password": PW}, ip="192.0.2.44", ua=IPAD).status_code == 401
    ro = call(anon, "POST", "/v1/auth/reauth:options", tok, k, ip="192.0.2.44", ua=IPAD).json()
    r = call(anon, "POST", "/v1/auth/reauth", tok, k, json_={"ticket": ro["ticket"], "credential": a.get(ro["publicKey"])}, ip="192.0.2.44", ua=IPAD)
    assert r.status_code == 200 and r.json()["method"] == "webauthn"


def test_revoke_other_sessions(anon, as_user):
    as_user("mfa.rev", "security_engineer")
    a, b = login(anon, "mfa.rev").json()["token"], login(anon, "mfa.rev").json()["token"]
    assert call(anon, "POST", "/v1/auth/sessions:revoke-others", a).json()["revoked"] >= 1
    assert call(anon, "GET", "/v1/auth/me", b).status_code == 401 and call(anon, "GET", "/v1/auth/me", a).status_code == 200
