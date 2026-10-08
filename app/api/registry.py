"""레지스트리·카탈로그·도식 항목·커버리지 API (PRD §12.3)."""
import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.coverage import report
from app import approvals, ledger, models, registry, review
from app.api.deps import Ctx, ctx, need, platform_scope, read_tenant, session

router = APIRouter(prefix="/v1", tags=["registry"], dependencies=[Depends(ctx)])


def agent_out(a: models.Agent) -> dict:
    return {"id": a.id, "itemId": a.item_id, "version": a.version, "name": a.name, "nameKo": a.name_ko,
            "series": a.series, "gate": a.gate, "isolation": a.isolation, "failMode": a.fail_mode,
            "latencyBudgetMs": a.latency_budget_ms, "status": a.status, "origin": a.origin,
            "standards": a.manifest["spec"]["standards"], "updatedAt": a.updated_at.isoformat() if a.updated_at else None}


@router.get("/agents")
def list_agents(s: Session = Depends(session)):
    return {"items": [agent_out(a) for a in registry.agents(s)]}


@router.get("/agents/{agent_id}")
def get_agent(agent_id: str, s: Session = Depends(session)):
    a = s.get(models.Agent, agent_id)
    if not a:
        raise HTTPException(404, f"agent {agent_id} 없음")
    out = agent_out(a) | {"manifest": a.manifest}
    if a.origin == "builtin" and a.status != "stopped":
        out["quality"] = registry.quality(a.id)
        rt = registry.runtime_agent(a.id)
        out["rules"], out["rulesEn"] = rt.rules, rt.rules_en
    return out


@router.post("/agents", status_code=201)
async def register_agent(request: Request, s: Session = Depends(session), c: Ctx = Depends(need("agent.register"))):
    who = c.name
    raw = await request.body()
    try:
        body = yaml.safe_load(raw) if raw else None     # JSON 은 YAML 의 부분집합 — application/json·yaml 모두 수용
    except yaml.YAMLError as exc:
        raise HTTPException(400, f"매니페스트 파싱 실패: {exc}") from exc
    if not isinstance(body, dict):
        raise HTTPException(422, {"stage": "R1", "detail": "매니페스트는 객체여야 한다"})
    if body.get("format") == review.BUNDLE_FORMAT:          # 서명된 번들 → R1~R5 심사
        rv, row = review.submit(s, body, who)
        s.commit()
        out = {"review": review_out(rv)}
        if rv.outcome == "rejected":
            raise HTTPException(422, out)
        return agent_out(row) | out
    try:
        row, r1_review = registry.register(s, body)
    except registry.RegistrationError as exc:
        raise HTTPException(422, {"stage": exc.stage, "detail": exc.detail}) from exc
    ledger.append(s, "agent", row.id, {"event": "registered", "by": who, "version": row.version, "review": r1_review})
    s.commit()
    return agent_out(row) | {"review": r1_review}


@router.get("/risk-items")
def risk_items(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """도식 80 항목과 적용 현황 (콘솔 위험 지도, PRD §11.6 영역 1) — 적용 현황은 주체의 테넌트 범위."""
    agents = {a.item_id: a for a in s.scalars(select(models.Agent))}
    bound: dict[str, str] = {}
    q = select(models.ProfileApplication).where(models.ProfileApplication.active.is_(True))
    if t := read_tenant(c, tenant):
        q = q.where(models.ProfileApplication.tenant == t)
    for app_ in s.scalars(q):
        for aid in app_.agent_ids:
            bound[aid] = app_.stage
    out = []
    for it in s.scalars(select(models.RiskItem)):
        a = agents.get(it.id)
        state = "missing" if not a else ("stopped" if a.status == "stopped" else
                                         "alert_only" if a.status == "alert_only" else
                                         {"observe": "observe", "partial": "partial", "enforce": "enforce"}
                                         .get(bound.get(a.id), "available"))
        out.append({"id": it.id, "kind": it.kind, "domain": it.domain, "nameEn": it.name_en, "nameKo": it.name_ko,
                    "priority": it.priority, "series": it.series, "stage": it.stage, "fr": it.fr,
                    "agent": a.id if a else None, "agentStatus": a.status if a else None, "state": state})
    order = {f"D{i}": i for i in range(1, 11)}
    out.sort(key=lambda x: (x["kind"] == "gap", order.get(x["domain"] or "", 99), x["id"]))
    return {"items": out}


@router.get("/coverage")
def coverage(stage: int | None = None):
    """도식 대비 커버리지 — CI 의 verify_coverage.py 와 동일 판정 (FR-P16)."""
    return report(stage)


def review_out(rv: models.AgentReview) -> dict:
    return {"id": rv.id, "agentId": rv.agent_id, "version": rv.version, "bundleSha256": rv.bundle_sha256,
            "outcome": rv.outcome, "stages": rv.stages, "submittedBy": rv.submitted_by, "createdAt": rv.created_at.isoformat()}


@router.get("/agents/{agent_id}/reviews")
def agent_reviews(agent_id: str, s: Session = Depends(session)):
    rows = s.scalars(select(models.AgentReview).where(models.AgentReview.agent_id == agent_id)
                     .order_by(models.AgentReview.created_at.desc()))
    return {"items": [review_out(r) for r in rows]}


class PublisherIn(BaseModel):
    keyId: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=1)
    publicKey: str = Field(min_length=40, max_length=64)
    tier: str = Field("community", pattern="^(official|partner|community)$")


@router.get("/publishers")
def list_publishers(s: Session = Depends(session)):
    return {"items": [{"keyId": k.key_id, "name": k.name, "publicKey": k.public_key, "active": k.active, "addedBy": k.added_by,
                       "tier": k.tier}
                      for k in s.scalars(select(models.PublisherKey))]}


@router.post("/publishers", status_code=201)
def add_publisher(body: PublisherIn, s: Session = Depends(session), c: Ctx = Depends(need("publisher"))):
    import base64
    who = c.name
    try:
        if len(base64.b64decode(body.publicKey, validate=True)) != 32:
            raise ValueError
    except ValueError:
        raise HTTPException(422, "publicKey 는 base64 Ed25519 공개키(32바이트)") from None
    s.merge(models.PublisherKey(key_id=body.keyId, name=body.name, public_key=body.publicKey, active=True, added_by=who,
                                tier=body.tier))
    ledger.append(s, "agent", body.keyId, {"event": "publisher_trusted", "name": body.name, "by": who})
    s.commit()
    return {"keyId": body.keyId, "name": body.name, "active": True, "tier": body.tier}


class PromoteIn(BaseModel):
    reason: str = Field(min_length=4, max_length=300)


@router.post("/agents/{agent_id}:promote")
def promote(agent_id: str, body: PromoteIn, s: Session = Depends(session), c: Ctx = Depends(need("publisher"))):
    """격리 미달(L3 없음 → L1 대체)로 경보 전용 등록된 서드파티 에이전트의 차단 승격 요청 — 2인 승인 후 active (OQ2)."""
    platform_scope(s, c)
    a = s.get(models.Agent, agent_id)
    if a is None or a.origin != "api":
        raise HTTPException(404, f"서드파티 agent {agent_id} 없음")
    if a.status != "alert_only":
        raise HTTPException(409, f"경보 전용 상태가 아니다 ({a.status})")
    rv = s.scalars(select(models.AgentReview).where(models.AgentReview.agent_id == agent_id).order_by(models.AgentReview.created_at.desc())).first()
    if rv is None or (rv.stages.get("R5") or {}).get("result") != "passed":
        raise HTTPException(409, "품질 기준(R5) 미달 — 승격 대상 아님(재심사 필요)")
    import secrets as _s
    ap = approvals.create(s, _s.token_hex(16), "default", "offline", [], f"에이전트 {agent_id} 차단 승격 — 격리 미달(L1 대체) 감수", c.name,
                          required=2, action={"type": "agent_promote", "agent": agent_id, "review": rv.id, "reason": body.reason})
    ledger.append(s, "agent", agent_id, {"event": "promotion_requested", "approval": ap.id, "reason": body.reason, "by": c.name})
    s.commit()
    return {"approvalRef": ap.id, "agent": agent_id, "review": rv.id}
