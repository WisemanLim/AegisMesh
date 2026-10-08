"""콘솔 보조 API (SCR-B05·B06·C06·D07·R06·P02·Q02)."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import console, models, profiles, samples
from app.api.deps import Ctx, ctx, need, read_tenant, session, write_tenant

router = APIRouter(prefix="/v1", tags=["console"], dependencies=[Depends(ctx)])


@router.get("/search")
def search(q: str = Query(min_length=2, max_length=80), s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return console.search(s, q, read_tenant(c, None))


@router.get("/notifications")
def notifications(hours: int = Query(72, ge=1, le=720), s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    items = console.notifications(s, read_tenant(c, None), hours)
    return {"items": items, "counts": {sev: sum(i["severity"] == sev for i in items) for sev in ("critical", "high", "medium", "low", "info")}}


class PreviewIn(BaseModel):
    stage: str = Field("enforce", pattern="^(observe|partial|enforce)$")
    samples: list[dict] | None = None
    tenant: str | None = None
    alertDomains: list[str] | None = None         # 부분 차단 미선택 도메인 — 경보로 재계산 (SCR-C07)
    source: str = Field("corpus", pattern="^(corpus|traffic)$")   # traffic = 보존 중인 마스킹 실제 표본(OQ1)
    target: str | None = None


@router.post("/profiles/{pid}:preview")
def preview(pid: str, body: PreviewIn, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = write_tenant(s, c, body.tenant)
    if not profiles.visible(s.get(models.Profile, pid), t):
        raise HTTPException(404, f"profile {pid} 없음")
    smp = body.samples
    if body.source == "traffic":
        smp = samples.for_preview(s, t, body.target)
        if not smp:
            raise HTTPException(409, "실제 트래픽 표본 없음 — 데이터 보호에서 미리보기 표본 보존을 켠다(2인 승인)")
    return console.preview(s, t, pid, body.stage, smp, alert_domains=body.alertDomains)


@router.get("/topology")
def topology(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return console.topology(s)


@router.get("/data-protection")
def data_protection(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return console.data_protection(s, read_tenant(c, None))


class TerminateIn(BaseModel):
    reason: str = Field(min_length=1)
    tenant: str | None = None


@router.post("/rogue/{name}:terminate")
def terminate(name: str, body: TerminateIn, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    """이탈·좀비 에이전트 강제 종료 — 격리 목록(관문 즉시 차단) + 자격증명·토큰·워크로드 신원 폐기."""
    r = console.terminate_rogue(s, write_tenant(s, c, body.tenant), name, body.reason, c.name)
    s.commit()
    return r


class RedteamIn(BaseModel):
    agents: list[str] | None = None
    scenario: str = "internal-corpus"
    reason: str = Field(min_length=1)


@router.post("/redteam/campaigns:request", status_code=202)
def request_redteam(body: RedteamIn, s: Session = Depends(session), c: Ctx = Depends(need("redteam"))):
    """레드팀 실행 승인 (SCR-Q02) — 시나리오·대상(등록부)·격리 → 2인 승인 → 실행."""
    try:
        apr = console.request_redteam(s, body.agents, body.scenario, body.reason, c.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return {"approvalRef": apr.id, "status": apr.status, "scope": apr.action}


@router.get("/install/precheck")
def precheck(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """설치 사전 점검·검증 (SCR-A01·A10)."""
    return console.precheck(s)


@router.get("/setup/status")
def setup_status(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """첫 실행 마법사 단계·설치 후 경과(NFR-O1 30분 목표)."""
    return console.setup_status(s)


@router.post("/setup/verify")
def setup_verify(s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    """설치 검증 (SCR-A10) — 관문 도달·기동 검사·강등 기본값·누락 검증. 원장 기록."""
    r = console.setup_verify(s, c.name)
    s.commit()
    return r
