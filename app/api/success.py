"""성공 지표 API (원본 PRD §15.1 · PRD.md §5) — KPI 12종 실측과 단계 목표 비교, 일 1회 스냅샷(원장 kpi)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import success
from app.api.deps import Ctx, ctx, need, platform_scope, read_tenant, session

router = APIRouter(prefix="/v1/metrics", tags=["metrics"], dependencies=[Depends(ctx)])


@router.get("/success")
def success_metrics(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """테넌트 사용자는 자기 테넌트 값(관문 지연·전환·설명·재구성), 커버리지·품질·무결성은 플랫폼 공통."""
    return success.compute(s, read_tenant(c, tenant))


@router.post("/success:snapshot")
def success_snapshot(s: Session = Depends(session), c: Ctx = Depends(need("governance"))):
    """지금 기록 — 전체 원장 검증을 포함해 오래 걸릴 수 있다(worker 가 매일 같은 일을 한다)."""
    platform_scope(s, c)
    r = success.snapshot(s, c.name)
    s.commit()
    return r
