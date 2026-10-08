"""미리보기 표본 API (OQ1 · NFR-D1 · SCR-C06) — 보존 설정(켜기·확대 = 2인 승인), 마스킹 표본 조회·라벨·삭제."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import samples
from app.api.deps import Ctx, ctx, need, read_tenant, session, write_tenant

router = APIRouter(prefix="/v1/traffic-samples", tags=["samples"], dependencies=[Depends(ctx)])


def _call(fn):
    try:
        return fn()
    except samples.SampleError as exc:
        raise HTTPException(exc.status, exc.msg) from exc


@router.get("")
def listing(target: str | None = None, limit: int = Query(100, ge=1, le=500), tenant: str | None = None,
            s: Session = Depends(session), c: Ctx = Depends(need("quality"))):
    return samples.listing(s, read_tenant(c, tenant) or "default", target, limit)


@router.get("/settings")
def get_settings(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return samples.settings_of(s, read_tenant(c, tenant) or "default")


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    maxSamples: int = 1000
    days: int = 7


@router.put("/settings")
def put_settings(body: SettingsIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    """켜기·늘리기 = 2인 승인 요청(R07), 끄기·줄이기 = 즉시(끄면 표본 전부 삭제)."""
    r = _call(lambda: samples.request_change(s, write_tenant(s, c, tenant), body.enabled, body.maxSamples, body.days, c.name))
    s.commit()
    return r


class LabelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(None, pattern="^(benign|attack)$")


@router.put("/{sid}/label")
def put_label(sid: str, body: LabelIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("quality"))):
    r = _call(lambda: samples.label(s, write_tenant(s, c, tenant), sid, body.label, c.name))
    s.commit()
    return r


@router.delete("", status_code=200)
def clear(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = write_tenant(s, c, tenant)
    n = samples.clear(s, t)
    from app import ledger
    ledger.append(s, "privacy", "samples", {"event": "samples_cleared", "removed": n, "by": c.name}, t)
    s.commit()
    return {"removed": n}
