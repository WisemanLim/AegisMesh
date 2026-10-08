"""거버넌스·사건·위험 등록부·보고서·레드팀 API (FR-P06·P10·P11, D10, X08·X09)."""
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import governance, incidents, ledger, models, redteam, reports
from app.api.deps import Ctx, ctx, need, read_tenant, session, visible_or_404

router = APIRouter(prefix="/v1", tags=["governance"], dependencies=[Depends(ctx)])


# ── 사건 ─────────────────────────────────────────────────────
@router.get("/incidents")
def list_incidents(status: str | None = "open", tenant: str | None = None, s: Session = Depends(session),
                   c: Ctx = Depends(need("read"))):
    q = select(models.Incident).order_by(models.Incident.updated_at.desc())
    if t := read_tenant(c, tenant):
        q = q.where(models.Incident.tenant == t)
    if status:
        q = q.where(models.Incident.status == status)
    return {"items": [incidents.out(i) for i in s.scalars(q)]}


@router.get("/incidents/{iid}")
def get_incident(iid: str, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    i = s.get(models.Incident, iid)
    visible_or_404(c, i, f"incident {iid}")
    return incidents.out(i, detail=True, s=s)


class IncidentAction(BaseModel):
    note: str = ""


@router.post("/incidents/{iid}:contain")
def contain(iid: str, body: IncidentAction, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    who = c.name
    i = s.get(models.Incident, iid)
    visible_or_404(c, i, f"incident {iid}")
    i.contained = True
    ledger.append(s, "incident", i.id, {"event": "contained", "by": who, "note": body.note}, i.tenant)
    s.commit()
    return incidents.out(i)


@router.post("/incidents/{iid}:close")
def close(iid: str, body: IncidentAction, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    who = c.name
    i = s.get(models.Incident, iid)
    visible_or_404(c, i, f"incident {iid}")
    if not i.contained:
        raise HTTPException(409, "봉쇄(contain) 전에는 종결할 수 없다")
    i.status, i.closed_by = "closed", who
    ledger.append(s, "incident", i.id, {"event": "closed", "by": who, "note": body.note}, i.tenant)
    s.commit()
    return incidents.out(i)


# ── 위험 등록부 ───────────────────────────────────────────────
class RiskIn(BaseModel):
    title: str = Field(min_length=1)
    score: float | None = Field(None, ge=0, le=10)
    decision: str = Field("open", pattern="^(open|mitigate|accept|transfer|avoid)$")
    owner: str | None = None
    dueAt: datetime | None = None
    source: str | None = None


def risk_out(r: models.Risk) -> dict:
    return {"id": r.id, "title": r.title, "score": r.score, "decision": r.decision, "owner": r.owner,
            "dueAt": r.due_at.isoformat() if r.due_at else None, "status": r.status, "source": r.source}


@router.get("/risks")
def list_risks(s: Session = Depends(session), c: Ctx = Depends(need("governance"))):
    return {"items": [risk_out(r) for r in s.scalars(select(models.Risk).order_by(models.Risk.created_at.desc()))]}


@router.post("/risks", status_code=201)
def add_risk(body: RiskIn, s: Session = Depends(session), c: Ctx = Depends(need("governance"))):
    who = c.name
    if body.decision == "accept" and (not body.owner or not body.dueAt):
        raise HTTPException(422, "수용(accept) 결정은 책임자·기한 필수 (MSG-003)")
    r = models.Risk(id=f"R-{secrets.token_hex(3)}", title=body.title, score=body.score, decision=body.decision,
                    owner=body.owner, due_at=body.dueAt, source=body.source)
    s.add(r)
    s.flush()
    ledger.append(s, "risk", r.id, {"event": "registered", "by": who, **risk_out(r)})
    s.commit()
    return risk_out(r)


# ── 보고서 ───────────────────────────────────────────────────
@router.get("/reports")
def list_reports(lang: str = Query("ko", pattern="^(ko|en)$"), c: Ctx = Depends(need("report"))):
    return {"items": reports.frameworks(lang)}


@router.get("/reports/{fw}")
def report(fw: str, days: int = Query(30, ge=1, le=3650), format: str = Query("json", pattern="^(json|md)$"),
           lang: str = Query("ko", pattern="^(ko|en)$"), s: Session = Depends(session), c: Ctx = Depends(need("report"))):
    """통제 매핑 보고서 — lang=en 이면 제목·라벨·고지문 영어(NFR-C4)."""
    try:
        rep = reports.generate(s, fw, days, None if c.scope == "*" else c.scope, lang)
    except KeyError:
        raise HTTPException(404, f"framework {fw} 없음") from None
    s.commit()
    return PlainTextResponse(reports.markdown(rep), media_type="text/markdown; charset=utf-8") if format == "md" else rep


# ── 거버넌스 자체 점검 ─────────────────────────────────────────
@router.get("/governance/snapshot")
def snapshot(s: Session = Depends(session), c: Ctx = Depends(need("governance"))):
    return governance.snapshot(s)


@router.post("/governance:assess")
def assess(s: Session = Depends(session), c: Ctx = Depends(need("governance"))):
    r = governance.assess(s, c.name)
    s.commit()
    return r


# ── 레드팀 ───────────────────────────────────────────────────
@router.post("/redteam/campaigns:run")
def run_campaign(s: Session = Depends(session), c: Ctx = Depends(need("redteam"))):
    r = redteam.run_campaign(s, c.name)            # 이중 용도 통제 — 실행 주체를 반드시 남긴다(§13.1)
    s.commit()
    return r


@router.get("/redteam/campaigns")
def campaigns(limit: int = Query(20, le=200), agent: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """agent 를 주면 그 에이전트의 캠페인별 결과(탐지율·기준선·오탐률)도 — 거절 일관성 회귀 추이(SCR-E03)."""
    rows = ledger.records(s, kind="redteam", limit=limit, desc=True)
    return {"items": [{"seq": r.seq, "at": r.created_at, "by": r.body.get("by"), "agents": r.body.get("agents"),
                       "regressions": r.body.get("regressions"), "fairness": r.body.get("fairness"),
                       "durationMs": r.body.get("durationMs")}
                      | ({"result": next((x for x in r.body.get("results") or [] if x["agent"] == agent), None)} if agent else {})
                      for r in rows]}


# ── 시스템 카드 (D10-06) ──────────────────────────────────────
@router.get("/cards/{agent_id}", response_class=PlainTextResponse)
def card(agent_id: str, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    a = s.get(models.Agent, agent_id)
    if not a:
        raise HTTPException(404, f"agent {agent_id} 없음")
    m = a.manifest
    std = "; ".join(f"{k} {v['version']}: {', '.join(v['ids'])}" for k, v in m["spec"]["standards"].items())
    return (f"# 시스템 카드 — {a.id} {a.name_ko}\n\n- 이름: {a.name} v{a.version} ({a.origin})\n"
            f"- 도식 항목: {a.item_id} — {m['metadata']['source']['item']}\n- 계열·관문: {a.series} · {a.gate} · 격리 {a.isolation} · fail_{a.fail_mode}\n"
            f"- 판정 유형: {', '.join(m['spec']['verdicts'])}\n- 엔진: {', '.join(e['id'] + '(' + e['kind'] + ')' for e in m['spec']['engines']['available'])}\n"
            f"- 표준: {std}\n- 지연 예산: {a.latency_budget_ms}ms\n- 한계: 규칙 기반 엔진 — 시험 코퍼스 밖 변형에 미탐 가능. 원문은 보존하지 않는다(NFR-D1).\n"
            f"- 갱신: {a.updated_at.isoformat() if a.updated_at else '-'} (매니페스트에서 자동 생성)\n")
