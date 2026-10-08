"""워크로드 신원·동적 시크릿 API (FR-P07, SCR-R03)."""
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import identity, models, secrets_broker
from app.api.deps import (
    Ctx,
    ctx,
    need,
    read_tenant,
    session,
    visible_or_404,
    write_tenant,
)

public = APIRouter(prefix="/v1/identity", tags=["identity"])
router = APIRouter(prefix="/v1", tags=["identity"], dependencies=[Depends(ctx)])


@public.get("/jwks")
def jwks():
    """SPIFFE 신뢰 번들(JWKS) — 누구나 JWT-SVID 를 독립 검증할 수 있다."""
    return identity.jwks()


@router.get("/identity")
def status(s: Session = Depends(session), c: Ctx = Depends(need("identity"))):
    identity.sync(s)
    s.commit()
    return identity.status(s)


class RotateIn(BaseModel):
    force: bool = False


@router.post("/identity:rotate")
def rotate(body: RotateIn, s: Session = Depends(session), c: Ctx = Depends(need("identity"))):
    """정기 회전(수명 50% 도달분) 또는 즉시 전체 회전(사고 대응 — 기존 SVID 무효화 + 동적 시크릿 전부 회수)."""
    r = identity.rotate(s, c.name, body.force)
    if body.force:
        r["leasesRevoked"] = secrets_broker.revoke_all(s, None, c.name)
    s.commit()
    return r


@router.post("/identity/svid")
def svid(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    """서비스 계정의 JWT-SVID 발급·갱신(1시간). 사람 사용자는 OIDC·세션을 쓴다."""
    if c.user.kind != "service":
        raise HTTPException(403, "서비스 계정만 SVID 를 받는다")
    row = identity.register(s, "service", c.user.username, c.user.tenant or "platform")
    if row.status != "active":
        raise HTTPException(403, "폐기된 워크로드 신원")
    token = identity.issue(s, row)
    s.commit()
    return {"svid": token, "spiffeId": row.spiffe_id, "expiresAt": identity._utc(row.expires_at).isoformat(),
            "kid": json.loads(identity._unb64(token.split(".")[0])).get("kid"),
            "audience": [identity.AUDIENCE]}


class VerifyIn(BaseModel):
    token: str
    audience: str = identity.AUDIENCE


@router.post("/identity:verify")
def verify(body: VerifyIn, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    try:
        claims = identity.verify(s, body.token, body.audience)
    except identity.IdentityError as exc:
        return {"valid": False, "reason": exc.msg}
    return {"valid": True, "claims": claims}


@router.get("/identity/static-credentials")
def static_credentials(s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    return {"items": identity.static_credentials(s, None if c.platform else c.user.tenant)}


# ── 동적 시크릿 ───────────────────────────────────────────────
@router.get("/secrets/leases")
def leases(active: bool = False, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    q = select(models.SecretLease).order_by(models.SecretLease.issued_at.desc()).limit(200)
    if t := read_tenant(c, tenant):
        q = q.where(models.SecretLease.tenant == t)
    rows = [secrets_broker.out(r) for r in s.scalars(q)]
    return {"items": [r for r in rows if not active or r["state"] == "active"]}


class LeaseIn(BaseModel):
    path: str
    scopes: list[str]
    ttlSec: int = Field(300, ge=30, le=86400)
    holder: str | None = None
    tenant: str | None = None


@router.post("/secrets/leases", status_code=201)
def lease(body: LeaseIn, s: Session = Depends(session), c: Ctx = Depends(need("secrets.lease"))):
    t = write_tenant(s, c, body.tenant)
    holder = body.holder or (identity.spiffe("service", c.user.username, c.user.tenant or "platform")
                             if c.user.kind == "service" else c.name)
    try:
        r, secret = secrets_broker.issue(s, t, body.path, body.scopes, holder, body.ttlSec, c.name)
    except secrets_broker.LeaseError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    s.commit()
    return secrets_broker.out(r) | {"secret": secret}


class RenewIn(BaseModel):
    ttlSec: int = Field(300, ge=30, le=86400)


@router.post("/secrets/leases/{lid}:renew")
def renew(lid: str, body: RenewIn, s: Session = Depends(session), c: Ctx = Depends(need("secrets.lease"))):
    r = visible_or_404(c, s.get(models.SecretLease, lid), f"lease {lid}")
    try:
        secrets_broker.renew(s, r, body.ttlSec, c.name)
    except secrets_broker.LeaseError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    s.commit()
    return secrets_broker.out(r)


@router.post("/secrets/leases/{lid}:revoke")
def revoke(lid: str, s: Session = Depends(session), c: Ctx = Depends(need("secrets.lease"))):
    r = visible_or_404(c, s.get(models.SecretLease, lid), f"lease {lid}")
    secrets_broker.revoke(s, r, c.name)
    s.commit()
    return secrets_broker.out(r)


class IntrospectIn(BaseModel):
    secret: str
    scope: str | None = None


@router.post("/secrets:introspect")
def introspect(body: IntrospectIn, s: Session = Depends(session), c: Ctx = Depends(need("secrets.lease"))):
    out = secrets_broker.introspect(s, body.secret, body.scope, c.scope)
    s.commit()                                                          # OpenBao 에서 회수·만료된 임대를 여기 상태에도 반영
    return out


@router.get("/secrets/backend")
def secrets_backend(c: Ctx = Depends(need("read"))):
    """임대 엔진 상태 — builtin 또는 OpenBao(주소·봉인·판). 토큰은 내보내지 않는다."""
    return secrets_broker.backend_status()
