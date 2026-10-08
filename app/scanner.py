"""상시 점검 (C3, PRD §8.2) — 요청 경로 밖에서 대상(MCP 서버·플러그인·SBOM·IaC·로그 파이프라인 등)을 점검하고,
발견을 같은 원장에 쌓으며, 차단급 발견은 인라인 정책을 동적으로 바꾼다(격리 목록 → 관문이 즉시 참조)."""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.schemas import JudgeRequest, Subject
from app import findings, ledger, models, orchestrator, policy, registry

QUARANTINABLE = ("mcp_server", "plugin", "skill", "tool", "agent", "model", "package", "api_provider", "host")


def offline_agents(s: Session) -> list[str]:
    return [a.id for a in s.scalars(select(models.Agent).where(models.Agent.gate == "offline",
                                                              models.Agent.status.in_(("active", "alert_only")),
                                                              models.Agent.origin == "builtin").order_by(models.Agent.id))]


def run_scan(s: Session, artifact: dict, tenant: str = "default", target: models.ScanTarget | None = None,
             agent_ids: list[str] | None = None, by: str = "worker") -> dict:
    ids = agent_ids or offline_agents(s)
    rts = [registry.runtime_agent(i) for i in ids]
    req = JudgeRequest(gate="offline", subject=Subject(tenant=tenant), artifact=artifact, traceId=secrets.token_hex(16))
    # 테넌트 정책 네임스페이스. 플랫폼 자체 점검(거버넌스)은 기본 테넌트 정책을 기준선으로 쓴다.
    pol = policy.latest(s, "default", "default" if tenant == ledger.PLATFORM else tenant)
    spec = policy.spec_of(pol)
    run = orchestrator.run_gate("offline", req, rts, spec.agent_params)
    decision = policy.evaluate(run["findings"], spec, "enforce")
    eff = {d["findingId"]: d["effective"] for d in decision["decisions"]}
    for f in run["findings"]:
        findings.store(s, f, eff[f.id])
    from app import incidents
    opened = incidents.correlate(s, req, run["findings"], eff)
    hits = [d for d in decision["decisions"] if d["effective"] != "allow"]
    quarantined = None
    if decision["verdict"] == "block" and artifact.get("kind") == "runtime_events" and artifact.get("host"):
        quarantined = quarantine(s, tenant, "host", str(artifact["host"]),                     # 침해 호스트 자동 격리 (SCR-M03)
                                 "; ".join(d["ruleId"] for d in hits if d["effective"] == "block"),
                                 [d["findingId"] for d in hits], by)
    elif decision["verdict"] == "block" and artifact.get("kind") in QUARANTINABLE and artifact.get("name"):
        quarantined = quarantine(s, tenant, artifact["kind"], str(artifact["name"]),
                                 "; ".join(d["ruleId"] for d in hits if d["effective"] == "block"),
                                 [d["findingId"] for d in hits], by)
    summary = {"traceId": req.trace_id, "target": target.id if target else None, "kind": artifact.get("kind"),
               "name": artifact.get("name"), "verdict": decision["verdict"], "agents": ids,
               "hits": [{"agent": d["agent"], "ruleId": d["ruleId"], "effective": d["effective"]} for d in hits],
               "latencyMs": run["latencyMs"], "quarantine": quarantined.id if quarantined else None,
               "incidents": [i.id for i in opened], "by": by}
    ledger.append(s, "scan", target.id if target else req.trace_id, summary, tenant)
    from app import telemetry
    telemetry.record_gate("offline", tenant, req.trace_id, run, decision,
                          {"artifact.kind": artifact.get("kind"), "by": by})
    if target is not None:
        target.last_run_at, target.last_verdict = datetime.now(timezone.utc), decision["verdict"]
    return summary | {"findings": [f.dump() for f in run["findings"]]}


def quarantine(s: Session, tenant: str, kind: str, value: str, reason: str, finding_ids: list[str],
               by: str, expires_at: datetime | None = None) -> models.Quarantine:
    cur = s.scalars(select(models.Quarantine).where(models.Quarantine.tenant == tenant, models.Quarantine.kind == kind,
                                                    models.Quarantine.value == value, models.Quarantine.active.is_(True),
                                                    _live())).first()
    if cur:
        return cur
    q = models.Quarantine(id=f"qtn_{secrets.token_hex(6)}", tenant=tenant, kind=kind, value=value, reason=reason,
                          finding_ids=finding_ids, active=True, expires_at=expires_at)
    s.add(q)
    s.flush()
    ledger.append(s, "quarantine", q.id, {"event": "quarantined", "kind": kind, "value": value, "reason": reason,
                                          "findings": finding_ids, "by": by,
                                          "expiresAt": expires_at.isoformat() if expires_at else None}, tenant)
    return q


def _live():
    """기한이 없거나 아직 지나지 않은 격리."""
    from sqlalchemy import or_
    return or_(models.Quarantine.expires_at.is_(None), models.Quarantine.expires_at > datetime.now(timezone.utc))


def release(s: Session, qid: str, by: str) -> models.Quarantine:
    q = s.get(models.Quarantine, qid)
    if q is None:
        raise KeyError(qid)
    q.active, q.released_by = False, by
    ledger.append(s, "quarantine", q.id, {"event": "released", "by": by}, q.tenant)
    return q


def names_in(req: JudgeRequest) -> set[str]:
    """요청이 가리키는 도구·서버·에이전트 이름 후보 (MCP 도구명 mcp__server__tool 형식 포함)."""
    out: set[str] = set()
    if req.tool:
        out.add(req.tool.name)
        out |= {p for p in re.split(r"__|\.|:|/", req.tool.name) if p}
        for k in ("server", "mcp_server", "plugin", "skill", "agent", "model", "package"):
            if isinstance(req.tool.args.get(k), str):
                out.add(req.tool.args[k])
    peer = req.params.get("peer") or {}
    if isinstance(peer.get("name"), str):
        out.add(peer["name"])
    for p in (req.subject.principal, req.subject.on_behalf_of):
        if p is not None and p.type == "agent":
            out.add(p.id)
    return out


def match(s: Session, tenant: str, req: JudgeRequest) -> models.Quarantine | None:
    """도구·서버·에이전트 이름 격리 + 깊은 검사 격리(같은 주체·세션의 다음 요청, Epic 51)."""
    from sqlalchemy import and_, or_
    Q = models.Quarantine
    conds = []
    names = names_in(req)
    if names:
        conds.append(and_(Q.kind.notin_(("principal", "session")), Q.value.in_(names)))
    if req.subject.principal is not None:
        conds.append(and_(Q.kind == "principal", Q.value == req.subject.principal.id))
    if req.session is not None:
        conds.append(and_(Q.kind == "session", Q.value == req.session.id))
    if not conds:
        return None
    return s.scalars(select(Q).where(Q.tenant == tenant, Q.active.is_(True), _live(), or_(*conds))).first()


def due_targets(s: Session, now: datetime | None = None) -> list[models.ScanTarget]:
    now = now or datetime.now(timezone.utc)
    out = []
    for t in s.scalars(select(models.ScanTarget).where(models.ScanTarget.enabled.is_(True))):
        last = t.last_run_at.replace(tzinfo=timezone.utc) if t.last_run_at and t.last_run_at.tzinfo is None else t.last_run_at
        if last is None or (now - last).total_seconds() >= t.interval_sec:
            out.append(t)
    return out
