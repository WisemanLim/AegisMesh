"""동적 시크릿 (FR-P07, SCR-R03 #3) — 호출 단위·최소 범위(다운스코핑)·짧은 수명의 임대 자격증명.

- 경로는 테넌트 네임스페이스(`<tenant>/<path>`), 범위(scopes)는 하위 도구가 introspect 로 확인한다.
- 최대 수명(갱신 포함) = SECRET_LEASE_MAX_SEC(기본 15분). 회수·만료는 즉시 반영. 원문은 발급 응답 1회 — 저장은 해시만.
- SECRETS_BACKEND=openbao 면 임대 원문 = OpenBao 토큰(역할 aegis-lease) — 수명·갱신·회수·만료의 원본이 OpenBao 이고
  여기에는 접근자(accessor)·해시만 둔다. 확인(introspect)은 OpenBao 에 물어 보고, 연결이 안 되면 거부한다(fail-closed).
  전환 전에 내장 브로커로 낸 임대는 그대로 확인·회수된다. Vault(BUSL)는 기본값 제외(MSG-027).
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger, models, openbao
from app.core.config import settings

PATH = re.compile(r"^[a-z0-9][a-z0-9/_-]{1,100}$")
SCOPE = re.compile(r"^[a-z][a-z0-9_.:*-]{1,80}$")
PREFIX = "aeg_dyn_"


class LeaseError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def state(r: models.SecretLease, now: datetime | None = None) -> str:
    now = now or utcnow()
    return "revoked" if r.revoked_at else "expired" if _utc(r.expires_at) <= now else "active"


def out(r: models.SecretLease) -> dict:
    return {"id": r.id, "tenant": r.tenant, "path": r.path, "scopes": r.scopes, "holder": r.holder, "state": state(r),
            "issuedAt": _utc(r.issued_at).isoformat(), "expiresAt": _utc(r.expires_at).isoformat(),
            "maxExpiresAt": _utc(r.max_expires_at).isoformat(), "renewals": r.renewals, "revokedBy": r.revoked_by, "backend": r.backend}


def issue(s: Session, tenant: str, path: str, scopes: list[str], holder: str, ttl_sec: int, by: str) -> tuple[models.SecretLease, str]:
    if not PATH.match(path):
        raise LeaseError(422, "경로는 소문자·숫자·/_- (예: db/payments-readonly)")
    if not scopes or any(not SCOPE.match(x) for x in scopes):
        raise LeaseError(422, "범위 1개 이상, 예: tool:search_docs · db:read")
    if "*" in scopes:
        raise LeaseError(422, "전체 범위(*)는 발급하지 않는다 — 호출 단위 최소 범위")
    ttl = min(max(ttl_sec, 30), settings.secret_lease_max_sec)
    now = utcnow()
    lid, full, scopes = f"lse_{secrets.token_hex(6)}", f"{tenant}/{path}", sorted(set(scopes))
    backend, accessor = ("openbao" if openbao.enabled() else "builtin"), None
    if backend == "openbao":
        try:
            t = openbao.create(ttl, {"lease": lid, "tenant": tenant, "path": full, "scopes": ",".join(scopes), "holder": holder})
        except openbao.BaoError as exc:
            raise LeaseError(503 if exc.status >= 500 else 502, f"OpenBao 임대 발급 실패 — {exc.msg}") from exc
        secret, accessor, ttl = t["token"], t["accessor"], t["ttl"]
    else:
        secret = PREFIX + secrets.token_urlsafe(24)
    r = models.SecretLease(id=lid, tenant=tenant, path=full, scopes=scopes, holder=holder, secret_hash=_digest(secret), issued_at=now,
                           expires_at=now + timedelta(seconds=ttl), max_expires_at=now + timedelta(seconds=settings.secret_lease_max_sec),
                           renewals=0, backend=backend, accessor=accessor)
    s.add(r)
    s.flush()
    ledger.append(s, "secret", r.id, {"event": "lease_issued", "path": r.path, "scopes": r.scopes, "holder": holder,
                                      "ttlSec": ttl, "by": by, "backend": backend}, tenant)
    return r, secret


def renew(s: Session, r: models.SecretLease, ttl_sec: int, by: str) -> models.SecretLease:
    if state(r) != "active":
        raise LeaseError(409, f"임대 {r.id} {state(r)} — 갱신 불가")
    want = min(max(ttl_sec, 30), settings.secret_lease_max_sec)
    if r.backend == "openbao":
        try:
            want = openbao.renew(r.accessor, want)                     # OpenBao 가 explicit_max_ttl 로 자른 실제 수명
        except openbao.BaoError as exc:
            if exc.status >= 500:
                raise LeaseError(503, f"OpenBao 갱신 실패 — {exc.msg}") from exc
            _gone(s, r)
            raise LeaseError(409, f"임대 {r.id} OpenBao 에서 회수·만료됨 — 갱신 불가") from exc
    new_exp = min(utcnow() + timedelta(seconds=want), _utc(r.max_expires_at))
    r.expires_at, r.renewals = new_exp, r.renewals + 1
    ledger.append(s, "secret", r.id, {"event": "lease_renewed", "expiresAt": new_exp.isoformat(), "by": by, "backend": r.backend}, r.tenant)
    return r


def _bao_revoke(r: models.SecretLease) -> str | None:
    """OpenBao 쪽 회수 — 실패해도 여기 회수는 유지(introspect 가 먼저 거부)하고 오류를 원장에 남긴다."""
    if r.backend != "openbao" or not r.accessor:
        return None
    try:
        openbao.revoke(r.accessor)
        return None
    except openbao.BaoError as exc:
        return exc.msg


def _gone(s: Session, r: models.SecretLease) -> None:
    """OpenBao 에서 이미 회수·만료된 임대 — 목록·상태를 맞춘다."""
    if not r.revoked_at:
        r.revoked_at, r.revoked_by = utcnow(), "openbao"
        ledger.append(s, "secret", r.id, {"event": "lease_revoked", "by": "openbao", "reason": "OpenBao 에서 회수·만료", "backend": "openbao"},
                      r.tenant)


def revoke(s: Session, r: models.SecretLease, by: str) -> models.SecretLease:
    if not r.revoked_at:
        r.revoked_at, r.revoked_by = utcnow(), by
        err = _bao_revoke(r)
        ledger.append(s, "secret", r.id, {"event": "lease_revoked", "by": by, "backend": r.backend} | ({"openbaoError": err} if err else {}),
                      r.tenant)
    return r


def revoke_all(s: Session, tenant: str | None, by: str) -> int:
    """사고 대응 즉시 회전 — 활성 임대 전부 회수."""
    q = select(models.SecretLease).where(models.SecretLease.revoked_at.is_(None))
    if tenant:
        q = q.where(models.SecretLease.tenant == tenant)
    rows = [r for r in s.scalars(q) if state(r) == "active"]
    errors = 0
    for r in rows:
        r.revoked_at, r.revoked_by = utcnow(), by
        errors += _bao_revoke(r) is not None
    if rows:
        for t in sorted({r.tenant for r in rows}):
            ledger.append(s, "secret", "revoke-all", {"event": "leases_revoked", "count": sum(r.tenant == t for r in rows), "by": by}
                          | ({"openbaoErrors": errors} if errors else {}), t)
    return len(rows)


def introspect(s: Session, secret: str, scope: str | None = None, tenant_scope: str = "*") -> dict:
    """하위 도구·서비스가 받은 시크릿을 확인 (RFC 7662 형태) — 범위 밖 호출이면 active=false.
    다른 테넌트의 시크릿은 존재 자체를 드러내지 않는다(앱 계층 + PG RLS)."""
    r = s.scalars(select(models.SecretLease).where(models.SecretLease.secret_hash == _digest(secret))).first() if secret else None
    if r is not None and tenant_scope not in ("*", r.tenant):
        r = None
    if r is None:
        return {"active": False, "reason": "알 수 없는 시크릿"}
    st = state(r)
    if st != "active":
        return {"active": False, "reason": st, "lease": r.id}
    extra = {"backend": r.backend}
    if r.backend == "openbao":                                         # 원본에 묻는다 — OpenBao 에서 회수·만료됐으면 여기도 맞춘다
        try:
            data = openbao.lookup(r.accessor)
        except openbao.BaoError as exc:
            return {"active": False, "reason": f"확인 불가(fail-closed) — {exc.msg}", "lease": r.id}
        if data is None:
            _gone(s, r)
            return {"active": False, "reason": "OpenBao 에서 회수·만료됨", "lease": r.id}
        extra["ttl"] = int(data.get("ttl", 0))
    if scope and scope not in r.scopes:
        return {"active": False, "reason": f"범위 밖 — {scope} 없음 (다운스코핑)", "lease": r.id, "scopes": r.scopes}
    return {"active": True, "lease": r.id, "tenant": r.tenant, "path": r.path, "scopes": r.scopes, "holder": r.holder,
            "exp": int(_utc(r.expires_at).timestamp())} | extra


def backend_status() -> dict:
    return openbao.status() if openbao.enabled() else {"backend": "builtin", "ok": True}
