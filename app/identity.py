"""워크로드 신원 (FR-P07, SCR-R03) — SPIFFE JWT-SVID 내장 발급자.

- SPIFFE ID: spiffe://<td>/agent/<id> · spiffe://<td>/platform/<svc> · spiffe://<td>/tenant/<t>/svc/<user>
- JWT-SVID = EdDSA(Ed25519) 서명 JWS. 공개 번들 = JWKS (`GET /v1/identity/jwks`). 토큰 원문은 저장하지 않는다(jti·만료만).
- 수명 기본 1시간, 수명 50% 시점에 worker 가 회전. 사고 대응 시 전체 즉시 회전(원장 기록).
- 서비스 계정은 SVID 로 API 를 호출할 수 있다(정적 API 키 대신) — 서비스 계정 API 토큰으로 SVID 를 교환한다.
- IDENTITY_BACKEND=spire(Epic 53): 발급·키·회전은 SPIRE(Workload API, ES256), 신원 목록은 SPIRE 등록 항목으로 동기화(app/spire.py).
  검증은 두 서명(내장 EdDSA·SPIRE ES256)을 모두 받는다 — 전환 중 이미 나간 토큰은 만료까지 유효.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.ledger_verify import key_id_of
from app import kms, ledger, models, spire
from app.core.config import settings

AUDIENCE = "aegismesh"
PLATFORM = ("api", "worker", "web", "otel-collector")
STATIC_TOKEN_DAYS = 30                       # 만료 없음·30일 초과 API 토큰 = 정적 자격증명(D5-01)


class IdentityError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── 발급 키 ──────────────────────────────────────────────────
@lru_cache(maxsize=1)
def signing_key() -> Ed25519PrivateKey:
    raw = settings.svid_signing_key
    if raw and raw != "CHANGE_ME":
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
    return Ed25519PrivateKey.from_private_bytes(kms.secret_file(Path(settings.svid_key_file), ledger._new_ed25519))   # KMS 포장 저장(NFR-D2)


def _pub_raw() -> bytes:
    return signing_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kid() -> str:
    return key_id_of(_pub_raw())


def jwks() -> dict:
    """SPIFFE 신뢰 번들(JWT 권한) — JWKS 형식. spire 면 SPIRE 서버의 JWT 서명 키(+ 전환 중 검증용 내장 키)."""
    builtin = [{"kty": "OKP", "crv": "Ed25519", "x": _b64(_pub_raw()), "kid": kid(), "use": "jwt-svid", "alg": "EdDSA"}]
    keys = (spire.jwks()["keys"] + builtin) if spire.enabled() else builtin
    return {"keys": keys, "spiffe_sequence": 1, "spiffe_refresh_hint": settings.svid_ttl_sec // 2, "trust_domain": settings.spiffe_trust_domain}


# ── JWT-SVID ────────────────────────────────────────────────
def _sign(claims: dict) -> str:
    head = _b64(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": kid()}, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    sig = signing_key().sign(f"{head}.{body}".encode())
    return f"{head}.{body}.{_b64(sig)}"


def verify(s: Session, token: str, audience: str = AUDIENCE) -> dict:
    """서명·만료·대상(aud)·신원 폐기·즉시 회전(valid_after 이전 발급) 확인 → 클레임.
    정기 회전은 이전 SVID 를 만료까지 유효하게 둔다(SPIRE 와 같음) — 여러 복제본이 같은 신원을 써도 서로 무효화하지 않는다."""
    try:
        head_b, body_b, sig_b = token.split(".")
        head = json.loads(_unb64(head_b))
        claims = json.loads(_unb64(body_b))
    except (ValueError, json.JSONDecodeError) as exc:
        raise IdentityError(401, "JWT-SVID 형식 오류") from exc
    if head.get("alg") == "ES256" and spire.enabled():                  # SPIRE 가 발급한 JWT-SVID
        try:
            spire.verify_signature(head, f"{head_b}.{body_b}".encode(), _unb64(sig_b))
        except spire.SpireError as exc:
            raise IdentityError(401, str(exc)) from exc
    elif head.get("alg") != "EdDSA" or head.get("kid") != kid():
        raise IdentityError(401, "알 수 없는 서명 키")
    else:
        try:
            Ed25519PublicKey.from_public_bytes(_pub_raw()).verify(_unb64(sig_b), f"{head_b}.{body_b}".encode())
        except InvalidSignature as exc:
            raise IdentityError(401, "JWT-SVID 서명 불일치") from exc
    now = utcnow().timestamp()
    if claims.get("exp", 0) <= now:
        raise IdentityError(401, "JWT-SVID 만료")
    if audience not in (claims.get("aud") or []):
        raise IdentityError(401, f"대상(aud) 불일치 — {audience} 필요")
    row = s.get(models.WorkloadIdentity, claims.get("sub", ""))
    if row is None or row.status != "active":
        raise IdentityError(401, "폐기된 워크로드 신원")
    if row.valid_after and claims.get("iat", 0) < int(_utc(row.valid_after).timestamp()):
        raise IdentityError(401, "즉시 회전으로 무효화된 JWT-SVID — 다시 발급")
    return claims


def spiffe(kind: str, ref: str, tenant: str | None = None) -> str:
    td = settings.spiffe_trust_domain
    return {"agent": f"spiffe://{td}/agent/{ref}", "platform": f"spiffe://{td}/platform/{ref}"}.get(
        kind, f"spiffe://{td}/tenant/{tenant}/svc/{ref}")


def issue(s: Session, row: models.WorkloadIdentity, audience: list[str] | None = None) -> str:
    if spire.enabled():
        return _issue_spire(row, audience)
    now = utcnow()
    jti = secrets.token_hex(16)
    exp = now + timedelta(seconds=row.ttl_sec)
    token = _sign({"iss": f"spiffe://{settings.spiffe_trust_domain}", "sub": row.spiffe_id, "aud": audience or [AUDIENCE],
                   "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "jti": jti})
    if row.jti:
        row.rotations += 1
    row.jti, row.issued_at, row.expires_at = jti, now, exp
    return token


def _issue_spire(row: models.WorkloadIdentity, audience: list[str] | None) -> str:
    """Workload API 에서 받는다. 즉시 회전 뒤에는 aud 에 세대 값을 더해 에이전트 캐시의 옛 토큰(iat < valid_after)을 피한다."""
    aud = list(audience or [AUDIENCE])
    if row.valid_after:
        aud.append(f"aegis-gen-{int(_utc(row.valid_after).timestamp())}")
    try:
        token = spire.fetch_jwt(row.spiffe_id, aud)
    except spire.SpireError:                                            # 막 등록된 신원 — 항목을 만들고 에이전트 동기화(수 초)를 기다린다
        try:
            spire.ensure({row.spiffe_id: row.ttl_sec}, set())
        except spire.SpireError as exc:
            raise IdentityError(503, str(exc)) from exc
        token = None
        for _ in range(15):
            time.sleep(1)
            try:
                token = spire.fetch_jwt(row.spiffe_id, aud)
                break
            except spire.SpireError:
                continue
        if token is None:
            raise IdentityError(503, f"SPIRE 가 {row.spiffe_id} SVID 를 주지 않음(등록·에이전트 동기화 확인)")
    claims = json.loads(_unb64(token.split(".")[1]))
    if row.jti:
        row.rotations += 1
    row.jti = hashlib.sha256(token.encode()).hexdigest()[:32]          # SPIRE JWT 에는 jti 가 없다 — 토큰 지문만 기록
    row.issued_at = datetime.fromtimestamp(claims["iat"], timezone.utc)
    row.expires_at = datetime.fromtimestamp(claims["exp"], timezone.utc)
    return token


def register(s: Session, kind: str, ref: str, tenant: str | None = None) -> models.WorkloadIdentity:
    sid = spiffe(kind, ref, tenant)
    row = s.get(models.WorkloadIdentity, sid)
    if row is None:
        row = models.WorkloadIdentity(spiffe_id=sid, kind=kind, ref=ref, tenant=tenant, ttl_sec=settings.svid_ttl_sec,
                                      rotations=0, status="active", created_at=utcnow())
        s.add(row)
        s.flush()
    return row


def sync(s: Session) -> int:
    """활성 에이전트·플랫폼 구성요소·서비스 계정의 신원을 등록(없으면). 비활성 대상은 폐기."""
    n = 0
    for a in s.scalars(select(models.Agent)):
        row = register(s, "agent", a.id)
        row.status = "active" if a.status in ("active", "alert_only") else "revoked"
        n += 1
    for svc in PLATFORM:
        register(s, "platform", svc)
        n += 1
    for u in s.scalars(select(models.User).where(models.User.kind == "service")):
        row = register(s, "service", u.username, u.tenant or "platform")
        row.status = "active" if u.active else "revoked"
        n += 1
    if spire.enabled():                                                 # SPIRE 등록 항목도 같은 목록으로(없으면 만들고, 폐기는 지움)
        s.flush()
        rows = list(s.scalars(select(models.WorkloadIdentity)))
        spire.ensure({r.spiffe_id: r.ttl_sec for r in rows if r.status == "active"}, {r.spiffe_id for r in rows if r.status != "active"})
    return n


def due(row: models.WorkloadIdentity, now: datetime) -> bool:
    if row.status != "active":
        return False
    if row.issued_at is None or row.expires_at is None:
        return True
    issued, exp = _utc(row.issued_at), _utc(row.expires_at)
    return now >= issued + (exp - issued) / 2            # 수명 50% 시점 자동 회전


def rotate(s: Session, by: str, force: bool = False) -> dict:
    """정기 회전(worker): 에이전트·플랫폼 신원을 수명 50% 시점에 재발급 — 전달은 워크로드 API(SPIRE 에이전트 역할) 몫이라
    여기서는 jti·만료만 기록한다. 서비스 계정은 스스로 교환 엔드포인트로 갱신한다.
    즉시 회전(force, 사고 대응): 모든 신원의 기존 SVID 를 무효화(valid_after=지금)하고 재발급한다."""
    sync(s)
    now = utcnow()
    active = list(s.scalars(select(models.WorkloadIdentity).where(models.WorkloadIdentity.status == "active")))
    if force:
        for r in active:
            r.valid_after = now
    rows = [r for r in active if r.kind != "service" and (force or due(r, now))]
    if spire.enabled():                                                 # SPIRE 에이전트가 수명 50% 에 스스로 회전 — 여기선 발급하지 않는다
        rows = []
    for r in rows:
        issue(s, r)
    result = {"rotated": len(rows), "invalidated": len(active) if force else 0, "force": force, "by": by, "ttlSec": settings.svid_ttl_sec,
              "backend": settings.identity_backend,
              "byKind": {k: sum(r.kind == k for r in rows) for k in ("agent", "platform", "service")}}
    if rows or force:
        ledger.append(s, "identity", "rotation", {"event": "svid_rotated", **result})
    return result


def status(s: Session) -> dict:
    rows = list(s.scalars(select(models.WorkloadIdentity).order_by(models.WorkloadIdentity.kind, models.WorkloadIdentity.spiffe_id)))
    now = utcnow()
    active = [r for r in rows if r.status == "active"]
    nxt = min((_utc(r.issued_at) + (_utc(r.expires_at) - _utc(r.issued_at)) / 2 for r in active if r.issued_at and r.expires_at), default=None)
    last = ledger.records(s, kind="identity", limit=1, desc=True)
    sp = spire.status() if spire.enabled() else None
    return {"trustDomain": settings.spiffe_trust_domain, "issuer": f"spiffe://{settings.spiffe_trust_domain}", "kid": kid(),
            "backend": settings.identity_backend, "spire": sp,
            "algorithm": "ES256 (SPIRE)" if sp else "EdDSA (Ed25519)", "ttlSec": settings.svid_ttl_sec, "rotateAt": "수명 50%",
            "counts": {k: sum(r.kind == k and r.status == "active" for r in rows) for k in ("agent", "platform", "service")},
            "valid": sum(1 for r in active if r.expires_at and _utc(r.expires_at) > now),
            "expired": sum(1 for r in active if not r.expires_at or _utc(r.expires_at) <= now),
            "revoked": sum(r.status != "active" for r in rows), "nextRotation": nxt.isoformat() if nxt else None,
            "lastRotation": last[0].body | {"at": last[0].created_at} if last else None,
            "items": [{"spiffeId": r.spiffe_id, "kind": r.kind, "ref": r.ref, "tenant": r.tenant, "status": r.status,
                       "issuedAt": _utc(r.issued_at).isoformat() if r.issued_at else None,
                       "expiresAt": _utc(r.expires_at).isoformat() if r.expires_at else None, "rotations": r.rotations} for r in rows]}


def static_credentials(s: Session, tenant: str | None = None) -> list[dict]:
    """정적 자격증명 점검 (D5-01, SCR-R03 #6) — 서비스 계정의 만료 없음·장기 API 토큰."""
    q = (select(models.AuthSession, models.User).join(models.User, models.User.id == models.AuthSession.user_id)
         .where(models.AuthSession.kind == "api_token", models.AuthSession.revoked_at.is_(None)))
    if tenant:
        q = q.where(models.User.tenant == tenant)
    out = []
    for row, u in s.execute(q):
        long_lived = row.expires_at is None or (_utc(row.expires_at) - _utc(row.created_at)).days > STATIC_TOKEN_DAYS
        if long_lived:
            out.append({"token": row.id, "name": row.name, "user": u.username, "tenant": u.tenant, "kind": u.kind,
                        "createdAt": row.created_at.isoformat(), "expiresAt": row.expires_at.isoformat() if row.expires_at else None,
                        "advice": "SVID(1시간·자동 회전) 또는 만료 있는 토큰으로 교체 후 폐기"})
    return out
