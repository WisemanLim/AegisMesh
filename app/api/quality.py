"""판정 품질 API (NFR-Q1·Q2·Q6, SCR-O02·Q04) — 이의·라벨, 오탐 예산, 골든셋 재생, 공개 공격 코퍼스 미탐률."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models, quality
from app.api.deps import Ctx, ctx, need, platform_scope, read_tenant, session, visible_or_404

router = APIRouter(prefix="/v1", tags=["quality"], dependencies=[Depends(ctx)])


def _err(exc: quality.QualityError):
    raise HTTPException(exc.status, exc.msg) from exc


class AppealIn(BaseModel):
    reason: str = Field("false_positive", pattern="^(false_positive|wrong_rule|other)$")
    detail: str = Field("", max_length=500)
    method: str = Field("human", pattern="^(human|rejudge)$")
    sample: dict | None = None                       # 마스킹한 재현 표본 (JudgeRequest 모양) — 원문은 자동 보존하지 않는다


@router.post("/findings/{fid}:appeal", status_code=201)
def appeal(fid: str, body: AppealIn, s: Session = Depends(session), c: Ctx = Depends(need("quality"))):
    row = s.get(models.Finding, fid)
    visible_or_404(c, row, f"finding {fid}")
    try:
        lbl = quality.appeal(s, row, c.name, body.reason, body.detail, body.method, body.sample)
    except quality.QualityError as exc:
        _err(exc)
    s.commit()
    return quality.label_out(lbl)


@router.get("/findings/{fid}/appeals")
def finding_appeals(fid: str, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    row = s.get(models.Finding, fid)
    visible_or_404(c, row, f"finding {fid}")
    rows = s.scalars(select(models.FindingLabel).where(models.FindingLabel.finding_id == fid)
                     .order_by(models.FindingLabel.requested_at.desc()))
    return {"items": [quality.label_out(r) for r in rows], "trust": quality.trust(s, row.agent_id)}


@router.get("/appeals")
def appeals(status: str | None = None, agent: str | None = None, tenant: str | None = None,
            s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    q = select(models.FindingLabel)
    if t := read_tenant(c, tenant):
        q = q.where(models.FindingLabel.tenant == t)
    if status:
        q = q.where(models.FindingLabel.status == status)
    if agent:
        q = q.where(models.FindingLabel.agent_id == agent)
    return {"items": [quality.label_out(r) for r in s.scalars(q.order_by(models.FindingLabel.requested_at.desc()).limit(200))]}


class DecideIn(BaseModel):
    label: str = Field(pattern="^(fp|tp)$")
    note: str = Field("", max_length=300)


@router.post("/appeals/{lid}:decide")
def decide(lid: str, body: DecideIn, s: Session = Depends(session), c: Ctx = Depends(need("quality"))):
    row = s.get(models.FindingLabel, lid)
    visible_or_404(c, row, f"appeal {lid}")
    try:
        out = quality.decide(s, row, c.name, body.label, body.note)
    except quality.QualityError as exc:
        _err(exc)
    s.commit()
    return out


@router.get("/quality")
def summary(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return quality.summary(s, read_tenant(c, tenant))


@router.get("/quality/garak")
def garak_scan(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """외부 레드팀 엔진 garak 최근 결과(Epic 59) — 탐침별 무방비·관문 공격 성공률, garak 판. 없으면 null."""
    from app import garak
    return {"latest": garak.latest(s)}


@router.get("/quality/fp-budget")
def fp_budget(day: str | None = None, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return quality.fp_budget(s, day, read_tenant(c, tenant))


class ReplayIn(BaseModel):
    n: int = Field(10_000, ge=100, le=50_000)
    seed: int = 20260930


@router.post("/quality/golden:replay")
def golden(body: ReplayIn, s: Session = Depends(session), c: Ctx = Depends(need("quality.run"))):
    platform_scope(s, c)
    r = quality.golden_replay(s, c.name, body.n, body.seed)
    s.commit()
    return r


class CorpusIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    source: str = Field("", max_length=200)          # 예: JailbreakBench JBB-Behaviors (내부 미러)
    license: str = Field("", max_length=80)
    format: str = Field("jsonl", pattern="^(jsonl|csv)$")
    mode: str = Field("direct", pattern="^(direct|indirect|both)$")
    kind: str = Field("attack", pattern="^(attack|benign)$")            # attack = 미탐률 · benign = 오탐률
    variant: str = Field("dual", pattern="^(dual|rules-only|deep)$")    # rules-only = 분류기 끈 규칙 전용 · deep = 응답 후 안전 분류 모델 포함
    scope: str = Field("injection", pattern="^(injection|harmful-request)$")
    content: str = Field(min_length=1, max_length=10 * 1024 * 1024)


@router.post("/quality/corpora")
def corpus(body: CorpusIn, s: Session = Depends(session), c: Ctx = Depends(need("redteam"))):
    """폐쇄망 반입 코퍼스 재생 — 페이로드는 저장하지 않고 해시·건수·범주별 미탐률만 원장에 남긴다."""
    platform_scope(s, c)
    try:
        r = quality.corpus_eval(s, c.name, body.name, body.source, body.license, body.format, body.content, body.mode,
                                body.kind, body.variant, body.scope)
    except quality.QualityError as exc:
        _err(exc)
    s.commit()
    return r


@router.post("/quality/fp-budget:enforce")
def enforce(s: Session = Depends(session), c: Ctx = Depends(need("quality.run"))):
    platform_scope(s, c)
    acts = quality.enforce(s, c.name)
    s.commit()
    return {"actions": acts}
