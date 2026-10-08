"""거버넌스 스냅샷 (D10·X03·X08·X09·X10 의 점검 대상) — 플랫폼 자신의 정책·원장·관측·사건·레드팀 상태를 실제 데이터로 모은다."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.schemas import now_iso
from app import compliance, incidents, ledger, models, redteam, reports
from app.core.config import settings
from app.format_utils import iso_to_epoch

GOV_AGENTS = ["d10-01", "d10-02", "d10-03", "d10-04", "d10-05", "d10-06", "d10-07", "x03", "x08", "x09", "x10"]


def snapshot(s: Session) -> dict:
    now = datetime.now(timezone.utc)
    pols = {}
    for p in s.scalars(select(models.Policy)):
        key = f"{p.tenant}/{p.policy_id}"
        pols[key] = max(pols.get(key, 0), p.version)
    apps = list(s.scalars(select(models.ProfileApplication).where(models.ProfileApplication.active.is_(True))))
    v = ledger.verify(s)
    last_cp = dict(s.execute(select(models.LedgerCheckpoint.chain, func.max(models.LedgerCheckpoint.seq))
                             .group_by(models.LedgerCheckpoint.chain)).all())
    since_cp = max((s.scalar(select(func.count()).select_from(models.Evidence)
                             .where(models.Evidence.chain == c, models.Evidence.seq > last_cp.get(c, 0))) or 0
                    for c in s.scalars(select(models.LedgerChain.chain))), default=0)
    anon = s.scalar(select(func.count()).select_from(models.Evidence).where(models.Evidence.body["by"].as_string() == "anonymous")) or 0
    # 관측: 최근 24시간 관문 레코드
    since = (now - timedelta(hours=24)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    gates = list(s.scalars(select(models.Evidence).where(models.Evidence.kind == "gate", models.Evidence.created_at >= since)))
    n = len(gates)
    by_gate: dict[str, list[float]] = {}
    for g in gates:
        by_gate.setdefault(g.body.get("gate"), []).append(g.body.get("latencyMs", 0))

    def p95(xs):
        xs = sorted(xs)
        return xs[max(0, int(len(xs) * 0.95) - 1)] if xs else 0

    budgets = {"input": 80, "tool": 20, "output": 150}
    required = max((p.spec["spec"].get("evidence", {}).get("retentionDays", 0) for p in
                    (s.get(models.Profile, a.profile_id) for a in apps) if p), default=0)
    region_deny = any((s.get(models.Profile, a.profile_id).spec["spec"].get("region", {}) or {}).get("modelEgress") == "deny" for a in apps)
    controls = {}
    for fw in ("pipa", "eu-ai-act"):
        cat = reports.catalog(fw)
        active = {a.item_id for a in s.scalars(select(models.Agent).where(models.Agent.status.in_(("active", "alert_only"))))}
        controls[fw] = {"required": len(cat["controls"]),
                        "missing": [c["id"] for c in cat["controls"] if any(i not in active for i in c.get("items", []))]}
    rt = redteam.latest(s)
    rt_body = rt.body if rt else {}
    risks = [{"id": r.id, "decision": r.decision, "owner": r.owner, "score": r.score, "status": r.status,
              "dueAt": r.due_at.timestamp() if r.due_at else None} for r in s.scalars(select(models.Risk))]
    incs = [{"id": i.id, "severity": i.severity, "status": i.status, "contained": i.contained, "evidencePreserved": v["ok"],
             "runbook": bool(incidents.runbook_for(i.domain)),
             "ageHours": round((now - (i.created_at if i.created_at.tzinfo else i.created_at.replace(tzinfo=timezone.utc))).total_seconds() / 3600, 2)}
            for i in s.scalars(select(models.Incident).where(models.Incident.status == "open"))]
    day_ago = now - timedelta(hours=24)
    asks: dict[tuple, int] = {}
    for a in s.scalars(select(models.Approval).where(models.Approval.created_at >= day_ago)):
        k = (a.requested_by, a.summary.split(":")[-1].strip())
        asks[k] = asks.get(k, 0) + 1
    interactions = [{"agent": who, "kind": "approval", "action": act, "count": c} for (who, act), c in asks.items()]
    fp_rates = [r["fpRate"] for r in rt_body.get("results", [])]
    return {
        "kind": "governance_snapshot", "name": "aegismesh-platform", "generatedAt": now_iso(),
        "policies": [{"id": k, "version": ver} for k, ver in pols.items()],
        "applications": [{"profile": a.profile_id, "stage": a.stage, "target": a.target} for a in apps],
        "ledger": {"ok": v["ok"], "detail": v["detail"], "records": v["records"], "checkpoints": v["checkpoints"],
                   "sinceCheckpoint": since_cp},
        "approvals": {"pending": s.scalar(select(func.count()).select_from(models.Approval).where(models.Approval.status == "pending")),
                      "anonymousActions": anon},
        "controls": controls,
        "retention": {"requiredDays": required, "configuredDays": settings.evidence_retention_days},
        "modelEgress": settings.model_egress, "regionPolicy": "deny" if region_deny else "allow",
        "riskRegister": risks,
        "fairness": rt_body.get("fairness", []),
        "cards": [{"subject": a.id, "exists": True, "updatedAt": a.updated_at.timestamp() if a.updated_at else None}
                  for a in s.scalars(select(models.Agent))] + compliance.platform_cards(s),       # 에이전트 카드(매니페스트) + 시스템·모델 카드(SCR-N07)
        "monitoring": {"activeApplications": len(apps), "gateRecords24h": n,
                       "degradedRate": round(sum(1 for g in gates if g.body.get("degraded")) / n, 4) if n else 0.0,
                       "overBudgetRate": round(sum(1 for g in gates if g.body.get("overBudget")) / n, 4) if n else 0.0,
                       "collector": bool(settings.otel_endpoint)},
        "interactions": interactions,
        "incidents": incs,
        "redteam": {"lastRunAgeSec": (time.time() - iso_to_epoch(rt.created_at)) if rt else None,
                    "results": rt_body.get("results", []), "unregisteredTargets": []},
        "slo": {"gates": {g: {"p95": round(p95(xs), 3), "budget": budgets.get(g)} for g, xs in by_gate.items() if g in budgets},
                "fpRate": round(sum(fp_rates) / len(fp_rates), 4) if fp_rates else 0.0, "fpBudget": 0.005},
    }


def assess(s: Session, by: str) -> dict:
    from app import scanner
    snap = snapshot(s)
    return scanner.run_scan(s, snap, ledger.PLATFORM, agent_ids=GOV_AGENTS, by=by) | {"snapshot": snap}
