"""폐쇄망·신뢰 저장소·장터 API (FR-P14, NFR-C3, SCR-A05·R05·C10)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import airgap as bundle_fmt
from app import airgap, market, models
from app.api.deps import Ctx, ctx, need, session, write_tenant

router = APIRouter(prefix="/v1", tags=["airgap"], dependencies=[Depends(ctx)])


# ── 신뢰 저장소 ───────────────────────────────────────────────
@router.get("/trust-keys")
def trust_keys(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return {"items": [airgap.key_out(k) for k in s.scalars(select(models.TrustKey).order_by(models.TrustKey.created_at))]}


@router.get("/trust-keys:export")
def export_trust(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """오프라인 검증용 신뢰 번들 — `python -m aegis airgap verify b.tar.gz --trust trust.json`."""
    return {"keys": airgap.trust(s)}


class TrustIn(BaseModel):
    keyId: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=1, max_length=120)
    publicKey: str = Field(min_length=40, max_length=64)


@router.post("/trust-keys", status_code=202)
def add_trust(body: TrustIn, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    try:
        k = airgap.request_key(s, body.keyId, body.name, body.publicKey, c.name)
    except KeyError:
        raise HTTPException(409, f"trust key {body.keyId} 이미 있음") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return airgap.key_out(k) | {"note": "2인 승인 후 활성"}


class RevokeIn(BaseModel):
    reason: str = Field(min_length=1)


@router.post("/trust-keys/{kid}:revoke", status_code=202)
def revoke_trust(kid: str, body: RevokeIn, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    try:
        apr = airgap.request_revoke(s, kid, c.name, body.reason)
    except KeyError:
        raise HTTPException(404, f"활성 trust key {kid} 없음") from None
    s.commit()
    return {"approvalRef": apr.id, "status": apr.status}


# ── 번들 반입 ─────────────────────────────────────────────────
@router.post("/airgap/imports", status_code=201)
async def import_bundle(request: Request, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    """서명 번들(tar.gz) 반입 — 서명·해시·SBOM 취약점 기준 통과 시에만 적용. 실패해도 기록은 남는다(422)."""
    data = await request.body()
    if len(data) > bundle_fmt.MAX_BYTES:
        raise HTTPException(413, "번들이 너무 크다")
    imp = airgap.import_bundle(s, data, c.name)
    s.commit()
    out = airgap.import_out(imp)
    if imp.status != "imported":
        raise HTTPException(422, out)
    return out


@router.get("/airgap/imports")
def imports(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    rows = s.scalars(select(models.BundleImport).order_by(models.BundleImport.created_at.desc()).limit(50))
    return {"items": [airgap.import_out(i) for i in rows]}


@router.get("/sbom")
def sbom(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """제품 자체 릴리스 SBOM (CycloneDX 1.5) + 내부 취약점 DB 대조."""
    return airgap.release_sbom(s) | {"vulndb": airgap.vulndb().get("version")}


# ── 장터 ─────────────────────────────────────────────────────
@router.get("/market")
def listings(tier: str | None = None, status: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return {"items": [market.out(r) for r in market.listings(s, tier, status)], "tiers": market.TIERS}


class InstallIn(BaseModel):
    tenant: str | None = None


@router.post("/market/{lid}:request", status_code=202)
def request_install(lid: str, body: InstallIn, s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    """설치 요청 — 테넌트 관리자·플랫폼 관리자. 2인 승인 후 등록 심사(R1~R5)를 거쳐 설치."""
    row = s.get(models.MarketListing, lid)
    if row is None:
        raise HTTPException(404, f"listing {lid} 없음")
    tenant = write_tenant(s, c, body.tenant)
    try:
        apr = market.request_install(s, row, tenant, c.name)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    s.commit()
    return {"approvalRef": apr.id, "listing": row.id, "status": row.status}
