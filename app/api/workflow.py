"""작업 흐름 API (SCR-O06·B07·O07·R05) — 승인 결정 문맥·트레이, 사고 대응 런북·포렌식 보존·재현, 업데이트·자체 SBOM."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import workflow
from app.api.deps import Ctx, ctx, need, read_tenant, session

router = APIRouter(prefix="/v1", tags=["workflow"], dependencies=[Depends(ctx)])


@router.get("/approvals:tray")
def tray(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return workflow.tray(s, read_tenant(c, tenant), c.name)


@router.get("/approvals/{aid}/context")
def approval_context(aid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    out = workflow.approval_context(s, read_tenant(c, tenant), aid)
    if out is None:
        raise HTTPException(404, f"승인 요청 {aid} 없음")
    return out


def _inc(fn):
    try:
        return fn()
    except KeyError as exc:
        raise HTTPException(404, f"사건 {exc} 없음") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/incidents/{iid}/response")
def incident_response(iid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return _inc(lambda: workflow.response(s, read_tenant(c, tenant), iid))


class StepIn(BaseModel):
    step: str
    note: str = Field("", max_length=300)


@router.post("/incidents/{iid}/steps")
def run_step(iid: str, body: StepIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    r = _inc(lambda: workflow.run_step(s, read_tenant(c, tenant), iid, body.step, body.note, c.name))
    s.commit()
    return r


@router.post("/incidents/{iid}:preserve")
def preserve(iid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    r = _inc(lambda: workflow.preserve(s, read_tenant(c, tenant), iid, c.name))
    s.commit()
    return r


@router.post("/incidents/{iid}:replay")
def replay(iid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    r = _inc(lambda: workflow.replay(s, read_tenant(c, tenant), iid, c.name))
    s.commit()
    return r


@router.get("/updates")
def updates(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return workflow.updates(s)


@router.post("/updates/agents/{aid}:reload")
def reload_agent(aid: str, s: Session = Depends(session), c: Ctx = Depends(need("publisher"))):
    """롤링 교체 1건 — 품질 게이트 통과 시에만 교체, 실패하면 기존 인스턴스 유지(자동 롤백)."""
    try:
        r = workflow.reload_agent(s, aid, c.name)
    except KeyError:
        raise HTTPException(404, f"agent {aid} 없음") from None
    s.commit()
    return r


@router.get("/updates/sbom")
def sbom(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    r = workflow.release_sbom(s)
    return JSONResponse(r, headers={"content-disposition": 'attachment; filename="aegismesh-sbom.cdx.json"'})
