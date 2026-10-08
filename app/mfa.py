"""로그인 강화 (SCR-B02 · FR-D5-01·03) — 2단계 인증(패스키 우선·인증 앱 OTP 대체), DPoP 세션 바인딩,
새 기기·위치 재인증(MSG-030), 탈취 토큰 재사용 → 사용자 세션 전체 폐기 + 사건(D5-03 판정).

기기 = 브라우저·OS 계열(원 User-Agent 를 남기지 않음), 위치 = IP 대역(/24·/48). 콘솔 요청은 웹 서버가 DPoP 로 묶여 있을 때만
X-Aegis-Client-IP/UA 를 믿는다(그 밖의 호출자는 소켓 주소·자기 UA).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, object_session

from aegis.schemas import JudgeRequest, Principal, Subject
from aegis.schemas import Session as SessionInfo
from app import auth, db, dpop, fido, findings, geo, incidents, ledger, models, registry, webauthn
from app.auth import AuthError, utcnow
from app.core.config import settings

CHALLENGE_TTL = timedelta(minutes=5)
REVIEW_OK = ("/v1/auth/me", "/v1/auth/logout", "/v1/auth/reauth", "/v1/auth/reauth:options", "/v1/auth/sessions")
ENROLL_OK = ("/v1/auth/me", "/v1/auth/logout", "/v1/auth/mfa", "/v1/auth/webauthn/register:options", "/v1/auth/webauthn/register",
             "/v1/auth/totp:setup", "/v1/auth/totp:confirm", "/v1/auth/sessions")
PRIVILEGED = frozenset({"platform_admin", "tenant_admin", "approver"})   # OQ3 — 2단계 필수 역할
DEFAULT_POLICY = {"mfa": "privileged", "aaguids": []}


def policy_of(s: Session, tenant: str | None) -> dict:
    t = s.get(models.Tenant, tenant) if tenant else None
    return DEFAULT_POLICY | ((t.auth_policy or {}) if t else {})


def required(s: Session, user: models.User) -> bool:
    """2단계 필수 여부 — 특권 역할은 항상, 테넌트가 all 이면 그 테넌트 사람 사용자 전원. 서비스 계정·API 토큰은 해당 없음."""
    if user.kind != "human":
        return False
    return bool(PRIVILEGED & set(user.roles)) or policy_of(s, user.tenant)["mfa"] == "all"


def unlock_enrollment(s: Session, row: models.AuthSession | None, user: models.User, method: str) -> None:
    """등록 전용 세션 → 첫 2단계 등록 완료 시 일반 세션(이번 로그인은 비밀번호 + 방금 등록한 수단)."""
    if row is not None and row.state == "enroll":
        row.state, row.mfa, row.review_reason = "ok", method, None
        ledger.append(s, "auth", user.id, {"event": "mfa_enrollment_completed", "user": user.username, "session": row.id, "method": method},
                      auth.home_chain(user))


def origins() -> list[str]:
    return [o.strip() for o in settings.webauthn_origins.split(",") if o.strip()]


# ── 기기·위치 ─────────────────────────────────────────────────
def device_of(ua: str) -> tuple[str, str]:
    ua = ua or ""
    br = next((n for p, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari"),
                              ("curl/", "curl"), ("python", "Python"), ("node", "Node")) if p.lower() in ua.lower()), "other")
    os_ = next((n for p, n in (("iPad", "iPadOS"), ("iPhone", "iOS"), ("Android", "Android"), ("Mac OS X", "macOS"), ("Macintosh", "macOS"),
                               ("Windows", "Windows"), ("Linux", "Linux")) if p in ua), "—")
    label = f"{br} · {os_}"
    return label, hashlib.sha256(label.encode()).hexdigest()[:16]


def location_of(ip: str | None) -> str | None:
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    net = ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False)
    return str(net)


def client_of(request, trusted: bool) -> tuple[str | None, str]:
    """(IP, UA) — 웹 서버가 전달한 값은 DPoP 로 묶인 세션(키를 웹 서버가 보관)일 때만 쓴다."""
    h = request.headers
    if trusted and h.get("x-aegis-client-ip"):
        return h.get("x-aegis-client-ip"), h.get("x-aegis-client-ua", "")
    return (request.client.host if request.client else None), h.get("user-agent", "")


def _place(row: models.AuthSession, p: dict | None) -> None:
    row.location, row.geo = (p or {}).get("net"), geo.label(p)
    row.geo_lat, row.geo_lon, row.geo_at = (p or {}).get("lat"), (p or {}).get("lon"), utcnow()


def _travel_text(frm: str | None, to: str | None, t: dict) -> str:
    return f"✈ {frm} → {to} · {t['km']:,} km / {t['minutes']:g} min"           # 기호만(언어 중립) — 화면이 문구를 붙인다


def bind(row: models.AuthSession, request, jkt: str | None, method: str) -> None:
    """새 세션을 이 기기·위치에 묶는다. 같은 사용자의 다른 활성 세션이 마지막으로 본 지점에서 불가능한 속도로 왔으면 재인증·경보."""
    ip, ua = client_of(request, bool(jkt))
    row.jkt, row.mfa = jkt, method
    row.device, row.device_hash = device_of(ua)
    p = geo.lookup(ip)
    _place(row, p)
    s = object_session(row)
    if s is None or row.user_id is None or not p or p["kind"] != "public":
        return
    prev = s.scalars(select(models.AuthSession).where(models.AuthSession.user_id == row.user_id, models.AuthSession.kind == "session",
                                                      models.AuthSession.revoked_at.is_(None), models.AuthSession.id != row.id,
                                                      models.AuthSession.geo_lat.is_not(None))
                     .order_by(models.AuthSession.geo_at.desc())).first()
    t = geo.travel(prev.geo_lat, prev.geo_lon, auth._utc(prev.geo_at), p, utcnow()) if prev and prev.geo_at else None
    if t:
        db.set_scope(s, "*")                             # 판정·원장 기록(시스템 대응)
        user = s.get(models.User, row.user_id)
        verdict, incs = _judge(s, user, row, SessionInfo(id=row.id, boundIp=prev.geo, ip=row.geo, travelKm=t["km"], travelKmh=t["kmh"]))
        row.state, row.review_reason = "review", _travel_text(prev.geo, row.geo, t)[:200]
        ledger.append(s, "auth", user.id, {"event": "impossible_travel", "user": user.username, "session": row.id, "previous": prev.id,
                                           "reason": row.review_reason, "verdict": verdict, "incidents": incs} | t, auth.home_chain(user))


# ── 인증 앱 OTP (RFC 6238, SHA-1·30초·6자리) ───────────────────
# OTP 비밀은 열 타입(kms.EncryptedText)이 KMS 봉투 암호화로 저장한다(Epic 49). 아래는 그 전 형식(세션 비밀 유도 키 AES-GCM) 읽기 전용.
def _seal_key() -> bytes:
    return hashlib.sha256(auth._secret() + b"|totp-seal").digest()


def _secret_of(user: models.User) -> str:
    v = user.totp_secret
    if re.fullmatch(r"[A-Z2-7]+", v):                                   # base32 평문 = KMS 열에서 풀린 값
        return v
    raw = base64.urlsafe_b64decode(v)                                   # 옛 봉인 형식
    return AESGCM(_seal_key()).decrypt(raw[:12], raw[12:], b"totp").decode()


def totp_code(secret_b32: str, step: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    d = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(int.from_bytes(d[o:o + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def totp_check(user: models.User, code: str) -> bool:
    if not user.totp_secret or not re.fullmatch(r"\d{6}", code or ""):
        return False
    sec, now = _secret_of(user), int(time.time() // 30)
    for step in (now - 1, now, now + 1):
        if hmac.compare_digest(totp_code(sec, step), code) and (user.totp_last_step is None or step > user.totp_last_step):
            user.totp_last_step = step                                  # 같은 코드 재사용 방지
            return True
    return False


def totp_setup(s: Session, user: models.User) -> dict:
    sec = base64.b32encode(os.urandom(20)).decode().rstrip("=")
    user.totp_secret, user.totp_enabled, user.totp_last_step = sec, False, None
    uri = f"otpauth://totp/{quote(settings.webauthn_rp_name)}:{quote(user.username)}?secret={sec}&issuer={quote(settings.webauthn_rp_name)}&digits=6&period=30"
    return {"secret": sec, "uri": uri}


def totp_confirm(s: Session, user: models.User, code: str) -> None:
    if not user.totp_secret or not totp_check(user, code):
        raise AuthError(422, "OTP 코드가 맞지 않다 — 인증 앱 시각 확인")
    user.totp_enabled = True
    ledger.append(s, "auth", user.id, {"event": "mfa_enrolled", "user": user.username, "method": "totp"}, auth.home_chain(user))


# ── WebAuthn ─────────────────────────────────────────────────
def _challenge(s: Session, user: models.User | None, purpose: str, jkt: str | None = None, meta: dict | None = None) -> models.MfaChallenge:
    s.execute(delete(models.MfaChallenge).where(models.MfaChallenge.expires_at < utcnow() - timedelta(hours=1)))
    row = models.MfaChallenge(id=secrets.token_hex(16), user_id=user.id if user else None, purpose=purpose,
                              challenge=webauthn.b64u(os.urandom(32)), jkt=jkt, meta=meta or {}, expires_at=utcnow() + CHALLENGE_TTL)
    s.add(row)
    s.flush()
    return row


def take(s: Session, cid: str, purpose: str, user: models.User | None = None) -> models.MfaChallenge:
    row = s.get(models.MfaChallenge, cid or "")
    if row is None or row.purpose != purpose or row.used_at is not None or auth._utc(row.expires_at) < utcnow() \
            or (user is not None and row.user_id != user.id):
        raise AuthError(401, "인증 요청이 만료됐거나 이미 쓰였다 — 다시 시작")
    row.used_at = utcnow()
    return row


def creds(s: Session, user: models.User) -> list[models.WebAuthnCredential]:
    return list(s.scalars(select(models.WebAuthnCredential).where(models.WebAuthnCredential.user_id == user.id)
                          .order_by(models.WebAuthnCredential.created_at)))


def methods(s: Session, user: models.User) -> list[str]:
    return (["webauthn"] if creds(s, user) else []) + (["totp"] if user.totp_enabled else [])


def _aaguids(s: Session, user: models.User) -> list[str]:
    return [a.replace("-", "").lower() for a in policy_of(s, user.tenant).get("aaguids") or []]


def registration_options(s: Session, user: models.User) -> dict:
    ch = _challenge(s, user, "register")
    allow = _aaguids(s, user)
    return {"ticket": ch.id, "aaguidAllowlist": allow, "publicKey": {
        "rp": {"id": settings.webauthn_rp_id, "name": settings.webauthn_rp_name},
        "user": {"id": webauthn.b64u(user.id.encode()), "name": user.username, "displayName": user.display_name or user.username},
        "challenge": ch.challenge, "timeout": 60000, "attestation": "direct" if allow else "none",   # 허용목록이 있으면 실제 AAGUID 를 받는다
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in (-7, -8, -257)],
        "authenticatorSelection": {"residentKey": "preferred", "userVerification": "required"},
        "excludeCredentials": [{"type": "public-key", "id": c.id, "transports": c.transports} for c in creds(s, user)]}}


def register(s: Session, user: models.User, ticket: str, cred: dict, name: str) -> models.WebAuthnCredential:
    ch = take(s, ticket, "register", user)
    try:
        r = webauthn.verify_registration(cred, ch.challenge, settings.webauthn_rp_id, origins())
    except webauthn.WebAuthnError as exc:
        raise AuthError(422, f"패스키 등록 실패 — {exc}") from exc
    if s.get(models.WebAuthnCredential, r["credentialId"]) is not None:
        raise AuthError(409, "이미 등록된 인증기")
    allow, mds = _aaguids(s, user), fido.load()
    proof = None
    try:
        if allow:                                                       # 허용목록 = 제조사 증명 체인으로 기종 확인(자기 신고 AAGUID 불신)
            if r["aaguid"] not in allow:
                raise fido.FidoError("aaguid_not_allowed", f"AAGUID {r['aaguid']} 가 허용목록에 없음")
            a = r["attestation"]
            proof = fido.verify_attestation(a["att"], a["authData"], a["clientDataHash"], r["aaguid"], mds)
        elif mds is not None and mds.problem(r["aaguid"]):              # 허용목록이 없어도 MDS 가 유출·우회를 보고한 기종은 거부
            raise fido.FidoError("mds_status", f"MDS 상태 {mds.problem(r['aaguid'])} — {mds.entry(r['aaguid'])['description']}")
    except fido.FidoError as exc:
        ledger.append(s, "auth", user.id, {"event": "mfa_rejected", "user": user.username, "aaguid": r["aaguid"], "fmt": r["fmt"],
                                           "reason": exc.reason, "detail": str(exc)[:200]}, auth.home_chain(user))
        raise AuthError(422, f"{'테넌트 정책상 허용되지 않은 인증기' if allow else '패스키 등록 거부'} — {exc}") from exc
    row = models.WebAuthnCredential(id=r["credentialId"], user_id=user.id, public_key=r["publicKey"], sign_count=r["signCount"],
                                    name=(name or "passkey")[:120], alg=r["alg"], aaguid=r["aaguid"], transports=r["transports"])
    s.add(row)
    ledger.append(s, "auth", user.id, {"event": "mfa_enrolled", "user": user.username, "method": "webauthn", "credential": row.id[:16],
                                       "alg": r["alg"], "aaguid": r["aaguid"],
                                       "attestation": proof or "self-reported"}, auth.home_chain(user))
    return row


def assertion_options(s: Session, user: models.User, purpose: str, jkt: str | None = None, meta: dict | None = None) -> dict:
    ch = _challenge(s, user, purpose, jkt, meta)
    return {"ticket": ch.id, "methods": methods(s, user), "publicKey": {
        "challenge": ch.challenge, "rpId": settings.webauthn_rp_id, "timeout": 60000, "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": c.id, "transports": c.transports} for c in creds(s, user)]}}


def check(s: Session, user: models.User, ch: models.MfaChallenge, credential: dict | None, code: str | None) -> str:
    """2단계 확인 → 사용한 수단. 실패는 로그인 실패 횟수에 더한다(5회 → 15분 잠금)."""
    try:
        if credential is not None:
            row = s.get(models.WebAuthnCredential, str(credential.get("rawId") or credential.get("id") or ""))
            if row is None or row.user_id != user.id:
                raise webauthn.WebAuthnError("등록되지 않은 인증기")
            row.sign_count = webauthn.verify_assertion(credential, ch.challenge, settings.webauthn_rp_id, origins(), row.public_key, row.sign_count)
            row.last_used_at = utcnow()
            return "webauthn"
        if code is not None and user.totp_enabled and totp_check(user, code):
            return "totp"
        raise webauthn.WebAuthnError("OTP 코드 불일치" if code is not None else "2단계 수단 없음")
    except webauthn.WebAuthnError as exc:
        user.failed_logins += 1
        event = "mfa_failed"
        if user.failed_logins >= auth.LOCK_AFTER:
            user.locked_until, user.failed_logins, event = utcnow() + auth.LOCK_FOR, 0, "locked"
        ledger.append(s, "auth", user.id, {"event": event, "user": user.username, "reason": str(exc)[:200]}, auth.home_chain(user))
        s.commit()
        raise AuthError(401, f"2단계 인증 실패 — {exc}") from exc


# ── 요청마다: DPoP 소유 증명 · 기기·위치 ─────────────────────────
def proof_key(proof: str | None, request, token: str | None) -> tuple[dict | None, str | None]:
    """(검증된 증명, 오류 코드). 증명이 없으면 (None, None)."""
    if not proof:
        return None, None
    try:
        return dpop.verify(proof, request.method, request.url.path, token), None
    except dpop.DpopError as exc:
        return None, exc.code


def _judge(s: Session, user: models.User, row: models.AuthSession, sess: SessionInfo) -> tuple[str, list[str]]:
    """D5-03 에이전트로 판정 → Finding·사건(상관). 판정·사건 ID."""
    req = JudgeRequest(gate="input", subject=Subject(tenant=user.tenant or "default", principal=Principal(id=user.username)),
                       session=sess, traceId=secrets.token_hex(16))
    f = registry.runtime_agent("d5-03").judge(req)
    findings.store(s, f, f.verdict)
    opened = incidents.correlate(s, req, [f], {f.id: f.verdict})
    return f.verdict, [i.id for i in opened]


def theft(s: Session, row: models.AuthSession, user: models.User, reason: str, presented: str | None, request) -> None:
    """탈취 토큰 재사용 — 사용자 세션 전체 폐기 + D5-03 판정·사건 + 원장. 폐기는 오류 응답과 함께 남긴다."""
    db.set_scope(s, "*")                                 # 범위 설정 전(ctx 인증 단계) 시스템 대응 — PG RLS 아래에서도 기록·폐기
    ip, _ = client_of(request, False)
    verdict, incs = _judge(s, user, row, SessionInfo(id=row.id, boundKey=row.jkt, proofKey=presented))
    n = auth.revoke_all(s, user)
    ledger.append(s, "auth", user.id, {"event": "token_replay", "user": user.username, "session": row.id, "reason": reason, "revoked": n,
                                       "verdict": verdict, "incidents": incs, "from": location_of(ip)}, auth.home_chain(user))
    s.commit()
    raise AuthError(401, f"세션 탈취 의심 — {reason}. 사용자 세션 {n}개 전체 폐기·사건 생성 (FR-D5-03)")


def enforce(s: Session, row: models.AuthSession, user: models.User, request, token: str, proof: str | None) -> None:
    if row.jkt:
        p, err = proof_key(proof, request, token)
        if p is None and err in ("stale", "mismatch"):
            raise AuthError(401, f"DPoP 증명 거부({err}) — 다시 요청")
        if p is None:
            theft(s, row, user, "소유 증명(DPoP) 없이 바인딩된 토큰 사용" if not proof else "위조된 DPoP 증명", None, request)
        if p["jkt"] != row.jkt:
            theft(s, row, user, "다른 키의 DPoP 증명", p["jkt"], request)
        jid = f"{row.jkt[:16]}:{p['jti']}"
        if s.get(models.DpopJti, jid) is not None:
            theft(s, row, user, "DPoP 증명 재사용(jti)", p["jkt"], request)
        s.add(models.DpopJti(id=jid, seen_at=utcnow()))
        if secrets.randbelow(100) == 0:                                  # 오래된 jti 정리(허용 오차의 몇 배만 보관)
            s.execute(delete(models.DpopJti).where(models.DpopJti.seen_at < utcnow() - timedelta(seconds=dpop.SKEW_SEC * 5)))
    if row.kind == "session" and (row.device_hash or row.location):
        ip, ua = client_of(request, bool(row.jkt))
        label, dh = device_of(ua)
        if not row.jkt:                                  # 묶이지 않은 API 세션(스크립트·CLI) — 도구마다 UA 가 달라 기기는 보지 않고 위치만
            dh = row.device_hash
        p = geo.lookup(ip)
        new_place = row.state == "ok" and geo.moved(row.geo, row.location, row.geo_lat, row.geo_lon, p)
        if row.state == "ok" and (dh != row.device_hash or new_place):
            db.set_scope(s, "*")                         # 판정·원장 기록(시스템 대응) — ctx 의 범위 설정 전
            both = bool(p) and p["kind"] == "public" and row.geo not in (None, "private", "unknown")
            frm, to = (row.geo, geo.label(p)) if both else (row.location, p and p["net"])      # 둘 다 지오면 나라·도시, 아니면 대역
            t = geo.travel(row.geo_lat, row.geo_lon, auth._utc(row.geo_at) if row.geo_at else None, p, utcnow()) if new_place else None
            parts = ([f"◆ {row.device} → {label}"] if dh != row.device_hash else []) + \
                    ([_travel_text(frm, to, t)] if t else [f"⌖ {frm} → {to}"] if new_place else [])
            why = " · ".join(parts)                      # 기호만(언어 중립) — 화면이 문구를 붙인다
            verdict, incs = _judge(s, user, row, SessionInfo(id=row.id, boundFingerprint=row.device_hash, fingerprint=dh, boundIp=frm, ip=to,
                                                             travelKm=t and t["km"], travelKmh=t and t["kmh"]))
            row.state, row.review_reason = "review", why[:200]
            ledger.append(s, "auth", user.id, {"event": "impossible_travel" if t else "session_anomaly", "user": user.username, "session": row.id,
                                               "reason": why, "verdict": verdict, "incidents": incs} | (t or {}), auth.home_chain(user))
            s.commit()
        elif row.state == "ok" and p and (p["net"] != row.location or not row.geo_at or utcnow() - auth._utc(row.geo_at) > timedelta(seconds=30)):
            if p.get("lat") is not None or row.geo_lat is None:
                _place(row, p)                           # 같은 도시 안 대역 변경(망 전환)·주기 갱신 — 지점·마지막으로 본 시각
            else:
                row.geo_at = utcnow()
        if row.state == "review" and request.url.path not in REVIEW_OK:
            raise AuthError(401, f"reauth_required: 새 위치·기기 감지 — 재인증 필요 (MSG-030) · {row.review_reason}")
    if row.state == "enroll" and request.url.path not in ENROLL_OK:
        raise AuthError(401, "mfa_enrollment_required: 특권 역할·테넌트 정책 — 보안 키·패스키 또는 인증 앱을 먼저 등록 (OQ3)")


def reauth(s: Session, row: models.AuthSession, user: models.User, request, ticket: str | None, credential: dict | None,
           code: str | None, password: str | None) -> dict:
    """재인증 — 2단계 수단이 있으면 그것으로만, 없으면 비밀번호. 성공하면 현재 기기·위치로 다시 묶는다."""
    if methods(s, user):
        ch = take(s, ticket or "", "reauth", user)
        used = check(s, user, ch, credential, code)
    else:
        if not password or not auth.check_password(password, user.password_hash):
            raise AuthError(401, "비밀번호가 올바르지 않다")
        used = "password"
    ip, ua = client_of(request, bool(row.jkt))
    before = (row.device, row.location)
    row.device, row.device_hash = device_of(ua)
    _place(row, geo.lookup(ip))
    row.state, row.review_reason = "ok", None
    ledger.append(s, "auth", user.id, {"event": "reauthenticated", "user": user.username, "session": row.id, "method": used,
                                       "from": list(before), "to": [row.device, row.location]}, auth.home_chain(user))
    return {"ok": True, "method": used, "device": row.device, "location": row.location}
