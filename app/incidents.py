"""사건 상관 분석 (FR-P06, X02) — 차단·승인요구 판정을 '같은 원인' 단위로 묶는다.

키 = 테넌트 + 행위 주체(사람·에이전트) 또는 점검 대상 이름 + 위험 도메인(D1…D10·X).
같은 키의 열린 사건이 시간 창(기본 15분) 안에서 갱신됐으면 이어 붙이고, 아니면 새 사건.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.schemas import Finding, JudgeRequest
from app import ledger, models

WINDOW = timedelta(minutes=15)
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RUNBOOKS = Path(__file__).resolve().parent.parent / "runbooks"


def domain_of(rule_id: str) -> str:
    item = rule_id.split(".")[0]
    return item.split("-")[0] if item.startswith("D") else "X"


def actor_of(req: JudgeRequest) -> str:
    sub = req.subject
    for p in (sub.on_behalf_of, sub.principal):
        if p is not None:
            return f"{p.type}:{p.id}"
    if req.artifact and req.artifact.get("name"):
        return f"{req.artifact.get('kind')}:{req.artifact['name']}"
    return "unknown"


def runbook_for(domain: str) -> str | None:
    p = RUNBOOKS / f"{domain.lower()}.md"
    return p.name if p.exists() else None


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


KEEP = 200        # 사건 행에 남기는 최근 trace·판정 ID 수 — 반복 공격에도 행 크기·갱신 비용이 일정(총계는 *_total)


def correlate(s: Session, req: JudgeRequest, findings: list[Finding], effective: dict[str, str],
              records: list | None = None, deltas: list | None = None) -> list[models.Incident]:
    """records 를 주면 원장 기록을 거기에 모은다(인라인 판정의 비동기 적재, NFR-L5) — 없으면 바로 적재.
    deltas 를 주면 열린 사건에 덧붙이기는 잠그지 않고 거기에 모은다 — 증적 작성기가 묶음마다 사건당 한 번 갱신(apply).
    같은 주체의 반복 공격이 사건 한 행을 요청마다 잠그던 병목(NFR-P1, Epic 66)을 없앤다. 새 사건은 그대로 바로 만든다."""
    hits = [f for f in findings if effective.get(f.id) in ("block", "require_approval")]
    if not hits:
        return []
    tenant, actor = req.subject.tenant, actor_of(req)
    by_domain: dict[str, list[Finding]] = {}
    for f in hits:
        by_domain.setdefault(domain_of(f.rule_id), []).append(f)
    now = datetime.now(timezone.utc)
    out = []
    for dom, fs in by_domain.items():
        key = f"{tenant}|{actor}|{dom}"
        inc = s.scalars(select(models.Incident).where(models.Incident.key == key, models.Incident.status == "open")
                        .order_by(models.Incident.updated_at.desc())).first()
        sev = max((f.severity for f in fs), key=SEV.__getitem__)
        if inc is None or now - _utc(inc.updated_at) > WINDOW:
            inc = models.Incident(id=f"inc_{secrets.token_hex(6)}", tenant=tenant, key=key, domain=dom, severity=sev,
                                  title=f"{dom} {fs[0].rule_id} — {actor}", status="open", contained=False,
                                  trace_ids=[], finding_ids=[], agent_ids=[], rule_ids=[])
            s.add(inc)
            event = "opened"
        else:
            new_rules = {f.rule_id for f in fs} - set(inc.rule_ids)
            if req.gate == "offline" and not new_rules:
                # 주기 점검이 같은 위반을 다시 찾았을 뿐 — 사건을 '지속 중'으로 갱신만 하고 판정을 쌓지 않는다
                inc.updated_at = now
                s.flush()
                out.append(inc)
                continue
            event = "correlated"
            if deltas is not None and req.gate != "offline":
                deltas.append({"id": inc.id, "severity": sev, "traces": sorted({f.trace_id for f in fs}), "findings": [f.id for f in fs],
                               "agents": sorted({f.agent.id for f in fs}), "rules": sorted({f.rule_id for f in fs}), "at": now.isoformat()})
                rec = ("incident", inc.id, {"event": event, "domain": dom, "severity": max(inc.severity, sev, key=SEV.__getitem__),
                                            "actor": actor, "findings": [f.id for f in fs], "rules": sorted({f.rule_id for f in fs})})
                if records is None:
                    ledger.append(s, *rec, tenant)
                else:
                    records.append(rec)
                out.append(inc)
                continue
            if SEV[sev] > SEV[inc.severity]:
                inc.severity = sev
        new_traces = sorted({f.trace_id for f in fs} - set(inc.trace_ids))
        inc.trace_ids = (list(inc.trace_ids) + new_traces)[-KEEP:]
        inc.finding_ids = (list(inc.finding_ids) + [f.id for f in fs])[-KEEP:]
        inc.trace_total = (inc.trace_total or 0) + len(new_traces)
        inc.finding_total = (inc.finding_total or 0) + len(fs)
        inc.agent_ids = sorted(set(inc.agent_ids) | {f.agent.id for f in fs})
        inc.rule_ids = sorted(set(inc.rule_ids) | {f.rule_id for f in fs})
        inc.updated_at = now
        s.flush()
        rec = ("incident", inc.id, {"event": event, "domain": dom, "severity": inc.severity, "actor": actor,
                                    "findings": [f.id for f in fs], "rules": sorted({f.rule_id for f in fs})})
        if records is None:
            ledger.append(s, *rec, tenant)
        else:
            records.append(rec)
        out.append(inc)
    return out


def apply(s: Session, deltas: list[dict]) -> None:
    """증적 작성기 — 묶음의 덧붙이기를 사건별로 모아 행마다 한 번 잠그고 갱신한다(id 순서 = 작성기 간 교착 없음)."""
    by: dict[str, list[dict]] = {}
    for d in deltas:
        by.setdefault(d["id"], []).append(d)
    for iid in sorted(by):
        inc = s.scalars(select(models.Incident).where(models.Incident.id == iid).with_for_update()).first()
        if inc is None:
            continue
        ds = by[iid]
        traces = [t for d in ds for t in d["traces"]]
        new_traces = sorted(set(traces) - set(inc.trace_ids))
        inc.trace_ids = (list(inc.trace_ids) + new_traces)[-KEEP:]
        inc.finding_ids = (list(inc.finding_ids) + [f for d in ds for f in d["findings"]])[-KEEP:]
        inc.trace_total = (inc.trace_total or 0) + len(new_traces)
        inc.finding_total = (inc.finding_total or 0) + sum(len(d["findings"]) for d in ds)
        inc.agent_ids = sorted(set(inc.agent_ids).union(*(d["agents"] for d in ds)))
        inc.rule_ids = sorted(set(inc.rule_ids).union(*(d["rules"] for d in ds)))
        inc.severity = max([inc.severity, *(d["severity"] for d in ds)], key=SEV.__getitem__)
        inc.updated_at = max(_utc(inc.updated_at), *(datetime.fromisoformat(d["at"]) for d in ds))
    s.flush()


def out(inc: models.Incident, detail: bool = False, s: Session | None = None) -> dict:
    d = {"id": inc.id, "tenant": inc.tenant, "title": inc.title, "domain": inc.domain, "severity": inc.severity,
         "status": inc.status, "contained": inc.contained, "traceIds": inc.trace_ids, "traceCount": inc.trace_total or len(inc.trace_ids),
         "findingCount": inc.finding_total or len(inc.finding_ids),
         "agents": inc.agent_ids, "rules": inc.rule_ids, "runbook": runbook_for(inc.domain),
         "createdAt": _utc(inc.created_at).isoformat(), "updatedAt": _utc(inc.updated_at).isoformat(), "closedBy": inc.closed_by}
    if detail and s is not None:
        rows = s.scalars(select(models.Finding).where(models.Finding.id.in_(inc.finding_ids))
                         .order_by(models.Finding.occurred_at)).all()
        d["timeline"] = [{"findingId": r.id, "at": r.occurred_at.isoformat(), "gate": r.gate, "agent": r.agent_id,
                          "ruleId": r.rule_id, "verdict": r.body.get("effectiveVerdict", r.verdict), "traceId": r.trace_id}
                         for r in rows]
        nodes = sorted({t["agent"] for t in d["timeline"]})
        edges = [[a["agent"], b["agent"]] for a, b in zip(d["timeline"], d["timeline"][1:]) if a["agent"] != b["agent"]]
        d["graph"] = {"nodes": nodes, "edges": edges}
        p, en = RUNBOOKS / f"{inc.domain.lower()}.md", RUNBOOKS / "en" / f"{inc.domain.lower()}.md"
        d["runbookText"] = p.read_text(encoding="utf-8") if p.exists() else None
        d["runbookTextEn"] = en.read_text(encoding="utf-8") if en.exists() else None      # NFR-C4 — 콘솔 en 모드
    return d
