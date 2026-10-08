"""컴플라이언스 API (SCR-N06 공정성·윤리 지표 · SCR-N07 시스템·모델 카드) — FR-D10-05·06."""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import compliance
from app.api.deps import Ctx, ctx, need, read_tenant, session, write_tenant

router = APIRouter(prefix="/v1/compliance", tags=["compliance"], dependencies=[Depends(ctx)])


def _call(fn):
    try:
        return fn()
    except compliance.ComplianceError as exc:
        raise HTTPException(exc.status, exc.msg) from exc


@router.get("/fairness")
def fairness(target: str | None = None, days: int = Query(7, ge=1, le=90), tenant: str | None = None,
             s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return compliance.fairness_view(s, read_tenant(c, tenant) or "default", target, days)


class MeasureIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str | None = None
    days: int = Field(7, ge=1, le=90)


@router.post("/fairness:measure")
def measure(body: MeasureIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("compliance.write"))):
    """지금 측정 — 집단별 차단율·성능 분해를 d10-05 로 판정, 원장 기록·추세, 한도 초과는 위험 등록부(MSG-023)."""
    r = compliance.measure(s, write_tenant(s, c, tenant), body.target, body.days, c.name)
    s.commit()
    return r


class AssessmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str
    summary: str = Field(min_length=1, max_length=1000)
    status: str = Field("approved", pattern="^(approved|draft)$")


@router.post("/fairness/assessments", status_code=201)
def assessment(body: AssessmentIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("compliance.write"))):
    r = _call(lambda: compliance.record_assessment(s, write_tenant(s, c, tenant), body.target, body.summary, body.status, c.name))
    s.commit()
    return r


class DisclosureIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    internal: bool = True
    external: bool = False


@router.put("/fairness/disclosure")
def disclosure(body: DisclosureIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("compliance.write"))):
    r = compliance.set_disclosure(s, write_tenant(s, c, tenant), body.internal, body.external, c.name)
    s.commit()
    return r


@router.get("/cards")
def cards(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return compliance.cards(s, read_tenant(c, tenant) or "default")


class GenerateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str | None = None


@router.post("/cards:generate")
def generate(body: GenerateIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("compliance.write"))):
    """자동 생성 — 메타데이터(대상·공급자·프로파일·정책·데이터셋·평가·공정성)에서 ko·en 카드 초안. 지문이 같으면 새 판 없음."""
    r = _call(lambda: compliance.generate(s, write_tenant(s, c, tenant), c.name, body.subject))
    s.commit()
    return {"items": r}


@router.get("/cards/{subject}/doc", response_class=PlainTextResponse)
def card_doc(subject: str, lang: str = Query("ko", pattern="^(ko|en)$"), version: int | None = None, tenant: str | None = None,
             s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return _call(lambda: compliance.card_doc(s, read_tenant(c, tenant) or "default", subject, lang, version))


class PublishIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    audiences: list[str]


@router.post("/cards/{subject}:publish")
def publish(subject: str, body: PublishIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("compliance.write"))):
    """검토 요청 → 승인 후 공개(내부·규제기관 제출·외부). 판 이력은 원장(덮어쓰기 없음)."""
    r = _call(lambda: compliance.request_publish(s, write_tenant(s, c, tenant), subject, body.audiences, c.name))
    s.commit()
    return r


@router.get("/deploy-gate")
def deploy_gate(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return compliance.deploy_gate(s, read_tenant(c, tenant) or "default")
