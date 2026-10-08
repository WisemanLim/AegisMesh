"""즉시 사용 마법사 API (SCR-C04·C05·C07) — 보호 대상, 프로파일 변경 비교, 단계 적용, 해제(이전 스냅샷 복귀)."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import instant, models, profiles
from app.api.deps import Ctx, ctx, need, read_tenant, session, write_tenant

router = APIRouter(prefix="/v1", tags=["instant"], dependencies=[Depends(ctx)])


def _call(fn):
    try:
        return fn()
    except instant.InstantError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/targets")
def list_targets(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = read_tenant(c, tenant) or "default"
    return {"tenant": t, "items": instant.targets(s, t)}


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    kind: str = "other"
    endpoint: str = Field(min_length=1, max_length=300)
    insertion: str = "gateway"
    modelProvider: str = Field("self-hosted", max_length=200)
    externalModel: bool = False
    mcpServers: list[str] = []
    egress: list[dict[str, Any]] = []


@router.post("/targets", status_code=201)
def save_target(body: TargetIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    r = _call(lambda: instant.save_target(s, t, body.model_dump(), c.name))
    s.commit()
    return r


@router.delete("/targets/{tid}", status_code=204)
def delete_target(tid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    _call(lambda: instant.delete_target(s, t, tid, c.name))
    s.commit()


@router.get("/profiles/{pid}/compare")
def compare(pid: str, target: str | None = None, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = read_tenant(c, tenant) or "default"
    if not profiles.visible(s.get(models.Profile, pid), t):
        raise HTTPException(404, f"profile {pid} 없음")
    return instant.compare(s, t, pid, target)


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str
    target: str
    stage: str = Field(pattern="^(observe|partial|enforce)$")
    blockDomains: list[str] | None = None
    confirmed: bool = False


@router.post("/instant:apply")
def apply(body: ApplyIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    if not profiles.visible(s.get(models.Profile, body.profile), t):
        raise HTTPException(404, f"profile {body.profile} 없음")
    r = _call(lambda: instant.apply_wizard(s, t, body.profile, body.target, body.stage, body.blockDomains, body.confirmed, c.name))
    s.commit()
    return r


class RollbackIn(BaseModel):
    target: str


@router.post("/instant:rollback")
def rollback(body: RollbackIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    r = _call(lambda: instant.rollback(s, t, body.target, c.name))
    s.commit()
    return r
