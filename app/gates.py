"""관문 상세·지연 예산(SCR-D02) · 강등 정책·장애 현황(SCR-D06) · 상단 바 관문 칩(CMP-15) — 원장·판정 집계(읽기 전용)와
재배치 요청(2인 승인)·무시(사유 원장 기록)."""
from __future__ import annotations

import math
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger, models, orchestrator, policy, quality

GATES = ("input", "tool", "output", "offline")
ACTIVE_MIN = 15          # 최근 15분 안에 강등 기록이 있으면 '강등 중' — 기록이 끊기면 자동 해제
MIN_CALLS = 20           # 재배치 제안 최소 호출 수(표본이 적으면 p95 를 믿지 않는다)
IGNORE_DAYS = 7          # 무시한 제안은 7일간 '무시됨(사유)'으로 표시
SCAN_LIMIT = 20000


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _q(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return round(xs[max(0, math.ceil(len(xs) * q) - 1)], 3)


def _gate_records(s: Session, tenant: str | None, since: datetime, kind: str = "gate") -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.kind == kind, models.Evidence.created_at >= _iso(since))
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    return list(s.scalars(q.order_by(models.Evidence.seq.desc()).limit(SCAN_LIMIT)))


def _bound(s: Session, tenant: str | None) -> list[str]:
    q = select(models.ProfileApplication).where(models.ProfileApplication.active.is_(True))
    if tenant:
        q = q.where(models.ProfileApplication.tenant == tenant)
    return sorted({i for a in s.scalars(q) for i in a.agent_ids})


def _spec(s: Session, tenant: str | None) -> policy.PolicySpec:
    return policy.spec_of(policy.latest(s, "default", tenant or "default"))


def _relocation_state(s: Session, tenant: str | None, gate: str) -> tuple[dict, dict]:
    """에이전트 → 대기 중 재배치 승인 / 최근 무시 사유."""
    pend = {}
    q = select(models.Approval).where(models.Approval.status == "pending", models.Approval.gate == gate)
    if tenant:
        q = q.where(models.Approval.tenant == tenant)
    for a in s.scalars(q):
        act = a.action or {}
        if act.get("type") in ("gate_relocate", "gate_restore"):
            pend[act["agent"]] = {"approval": a.id, "type": act["type"]}
    ign = {}
    for r in reversed(_gate_records(s, tenant, utcnow() - timedelta(days=IGNORE_DAYS), "gate_ops")):
        b = r.body
        if b.get("gate") == gate and b.get("event") == "relocation_ignored":
            ign[b["agent"]] = {"by": b.get("by"), "reason": b.get("reason"), "at": r.created_at}
    return pend, ign


# ── SCR-D02 관문 상세·지연 예산 ──────────────────────────────────
def detail(s: Session, tenant: str | None, gate: str, hours: int) -> dict:
    now = utcnow()
    since = now - timedelta(hours=hours)
    budget = orchestrator.GATE_BUDGET_MS.get(gate)
    hard = round(orchestrator.timeout_s(gate) * 1000) if budget else None
    spec = _spec(s, tenant)
    bud = spec.budgets or policy.Budgets()
    evs = [r for r in _gate_records(s, tenant, since) if r.body.get("gate") == gate]
    recs = [r.body for r in evs]
    cut = _iso(now - timedelta(minutes=ACTIVE_MIN))
    recent = {a for r in evs if r.created_at >= cut for a in r.body.get("degraded") or []}
    lat = [float(b.get("latencyMs", 0)) for b in recs]
    verdicts: dict[str, int] = {}
    for b in recs:
        verdicts[b.get("verdict", "allow")] = verdicts.get(b.get("verdict", "allow"), 0) + 1

    ids = _bound(s, tenant)
    agents = {a.id: a for a in s.scalars(select(models.Agent).where(models.Agent.id.in_(ids), models.Agent.gate == gate))} if ids else {}
    streak_since = now - timedelta(days=bud.over_streak)
    fq = select(models.Finding.agent_id, models.Finding.degraded, models.Finding.body, models.Finding.occurred_at).where(
        models.Finding.gate == gate, models.Finding.occurred_at >= min(since, streak_since))
    if tenant:
        fq = fq.where(models.Finding.tenant == tenant)
    per: dict[str, list[float]] = {}
    deg: dict[str, int] = {}
    daily: dict[str, dict[str, list[float]]] = {}
    for aid, degraded, body, at in s.execute(fq.order_by(models.Finding.occurred_at.desc()).limit(SCAN_LIMIT * 2)):
        ms = float(body.get("latencyMs", 0))
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        if at >= since:
            per.setdefault(aid, []).append(ms)
            deg[aid] = deg.get(aid, 0) + bool(degraded)
        if at >= streak_since:
            daily.setdefault(aid, {}).setdefault(at.date().isoformat(), []).append(ms)
    judged, fps = quality._counts(s, since, now, tenant)
    rows = []
    for aid, a in sorted(agents.items()):
        xs = per.get(aid, [])
        p95 = _q(xs, 0.95)
        days = sorted(daily.get(aid, {}).items(), reverse=True)
        over_days = 0
        for _d, v in days:
            if _q(v, 0.95) > a.latency_budget_ms:
                over_days += 1
            else:
                break
        state = ("relocated" if aid in spec.relocated else "degraded" if aid in recent else
                 "over" if xs and p95 > a.latency_budget_ms else "near" if xs and p95 >= 0.9 * a.latency_budget_ms else "ok")
        rows.append({"id": aid, "name": a.name, "nameKo": a.name_ko, "series": a.series, "failMode": a.fail_mode, "status": a.status,
                     "budgetMs": a.latency_budget_ms, "timeoutMs": hard, "calls": len(xs),
                     "p50Ms": _q(xs, 0.5), "p95Ms": p95, "p99Ms": _q(xs, 0.99), "degraded": deg.get(aid, 0),
                     "timeoutRate": round(deg.get(aid, 0) / len(xs), 4) if xs else 0.0,
                     "judged": judged.get(aid, 0), "fp": fps.get(aid, 0),
                     "fpRate": round(fps.get(aid, 0) / judged[aid], 5) if judged.get(aid) else 0.0,
                     "overDays": over_days, "dailyP95": [{"day": d, "p95Ms": _q(v, 0.95), "calls": len(v)} for d, v in days],
                     "state": state, "relocated": aid in spec.relocated})
    gate_p95 = _q(lat, 0.95)
    slowest = max((r["p95Ms"] for r in rows if not r["relocated"]), default=0.0)
    overhead = round(max(0.0, gate_p95 - slowest), 3) if lat else 0.0

    upper = float(budget) if budget else max(_q(lat, 0.99), 1.0)
    edges = [round(upper * i / 7, 1) for i in range(1, 8)]
    hist = [{"le": e, "count": 0, "over": bool(budget and e > budget * 0.9)} for e in edges] + \
           [{"le": None, "count": 0, "over": bool(budget)}]
    for x in lat:
        hist[next((i for i, e in enumerate(edges) if x <= e), len(edges))]["count"] += 1

    pend, ign = _relocation_state(s, tenant, gate)
    sugg = []
    if budget:
        for r in rows:
            if r["relocated"] or r["calls"] < MIN_CALLS or r["p95Ms"] <= r["budgetMs"]:
                continue
            others = max((x["p95Ms"] for x in rows if x["id"] != r["id"] and not x["relocated"]), default=0.0)
            expect = round(max(0.0, gate_p95 - max(0.0, r["p95Ms"] - others)), 1)
            sugg.append({"agent": r["id"], "nameKo": r["nameKo"], "name": r["name"], "p95Ms": r["p95Ms"], "budgetMs": r["budgetMs"],
                         "overDays": r["overDays"], "streak": bud.over_streak, "sustained": r["overDays"] >= bud.over_streak,
                         "gateP95Ms": gate_p95, "expectedGateP95Ms": expect,
                         "cost": "응답 후 판정·표시(차단 불가) — 상시 계열(C3) 비동기", "pending": pend.get(r["id"]), "ignored": ign.get(r["id"])})
    gate_of = dict(s.execute(select(models.Agent.id, models.Agent.gate).where(models.Agent.id.in_(spec.relocated))).all()) if spec.relocated else {}
    moved = [{"agent": a, "pending": pend.get(a)} for a in spec.relocated if gate_of.get(a) == gate]

    span_h = max(hours, 1)
    month = len(recs) / span_h * 24 * 30
    cost = None
    if bud.cost_per_1k is not None:
        monthly = round(month / 1000 * bud.cost_per_1k)
        cost = {"per1k": bud.cost_per_1k, "monthlyProjected": monthly, "monthlyBudget": bud.monthly_budget,
                "ratio": round(monthly / bud.monthly_budget, 4) if bud.monthly_budget else None}
    fpb = [r for r in quality.fp_budget(s, tenant=tenant)["agents"] if r["gate"] == gate]
    gj, gf = sum(r["judged"] for r in rows), sum(r["fp"] for r in rows)
    alerts = []
    if budget and lat and gate_p95 > budget:
        alerts.append({"severity": "high", "kind": "p95", "text": f"관문 p95 {gate_p95}ms > 예산 {budget}ms"})
    for r in rows:
        if r["overDays"] >= bud.over_streak:
            alerts.append({"severity": "medium", "kind": "streak", "text": f"{r['id']} p95 예산 몫 초과 {r['overDays']}일 연속"})
    if cost and cost["ratio"] is not None and cost["ratio"] >= bud.alert_ratio:
        alerts.append({"severity": "high" if cost["ratio"] >= 1 else "medium", "kind": "cost",
                       "text": f"월 방어 비용 예상 {cost['monthlyProjected']:,}원 — 예산의 {round(cost['ratio'] * 100)}%"})
    for r in fpb:
        if r["consumed"] >= quality.WARN_AT:
            alerts.append({"severity": "medium", "kind": "fp", "text": f"{r['agent']} 오탐 예산 {round(r['consumed'] * 100)}%"})
    return {"tenant": tenant or "*", "gate": gate, "hours": hours, "placement": "inline" if budget else "offline",
            "budgetMs": budget, "hardTimeoutMs": hard, "records": len(recs), "verdicts": verdicts,
            "p50Ms": _q(lat, 0.5), "p95Ms": gate_p95, "p99Ms": _q(lat, 0.99), "budgetRatio": round(gate_p95 / budget, 3) if budget and lat else None,
            "overBudget": sum(bool(b.get("overBudget")) for b in recs), "degraded": sum(bool(b.get("degraded")) for b in recs),
            "overheadMs": overhead, "budgetShareSum": sum(r["budgetMs"] for r in rows if not r["relocated"]),
            "rule": "병렬 합성 — 관문 p95 ≈ 가장 느린 에이전트 p95 + 합성 오버헤드 (에이전트 예산 몫은 합산이 아니라 최댓값이 관문 예산 안이어야 한다)",
            "agents": rows, "histogram": hist, "suggestions": sugg, "relocated": moved,
            "fp": {"judged": gj, "fp": gf, "rate": round(gf / gj, 5) if gj else 0.0, "target": quality.FP_RATE,
                   "budget": [{k: r[k] for k in ("agent", "consumed", "status", "fp", "budget")} for r in fpb]},
            "cost": cost, "budgets": bud.model_dump(by_alias=True), "alerts": alerts,
            "change": "재배치 적용·되돌림 = 정책 relocated 변경 → 2인 승인 후 새 정책 버전(10초 안 반영). 무시는 사유와 함께 원장 기록"}


def request_relocation(s: Session, tenant: str, gate: str, agent: str, by: str, reason: str, restore: bool = False) -> models.Approval:
    from app import approvals
    if gate not in policy.INLINE_GATES:
        raise ValueError("인라인 관문(input·tool·output)만 재배치")
    a = s.get(models.Agent, agent)
    if a is None or a.gate != gate:
        raise KeyError(agent)
    spec = _spec(s, tenant)
    if restore != (agent in spec.relocated):
        raise ValueError(f"{agent} 는 이미 {'인라인' if restore else '재배치됨'}")
    pend, _ = _relocation_state(s, tenant, gate)
    if agent in pend:
        raise ValueError(f"{agent} 재배치 승인 대기 중 ({pend[agent]['approval']})")
    kind = "gate_restore" if restore else "gate_relocate"
    what = "인라인 복귀" if restore else "상시 계열(비동기) 재배치 — 응답 후 판정, 차단 불가"
    return approvals.create(s, secrets.token_hex(16), tenant, gate, [], f"{gate} 관문 {agent} {what}: {reason}", by,
                            action={"type": kind, "policy": "default", "agent": agent, "gate": gate})


def ignore_relocation(s: Session, tenant: str, gate: str, agent: str, by: str, reason: str) -> models.Evidence:
    return ledger.append(s, "gate_ops", f"{gate}:{agent}", {"event": "relocation_ignored", "gate": gate, "agent": agent,
                                                            "by": by, "reason": reason}, tenant)


# ── SCR-D06 강등 정책·장애 현황 / CMP-15 관문 칩 ─────────────────────
def _episodes(recs: list[models.Evidence], gap_min: int = ACTIVE_MIN) -> list[dict]:
    """강등 기록(gate.degraded)을 에이전트별 연속 구간으로 묶는다 — 기록 사이가 gap_min 분 넘게 비면 새 구간."""
    by: dict[tuple[str, str], list[models.Evidence]] = {}
    for r in sorted(recs, key=lambda r: r.seq):
        for aid in r.body.get("degraded") or []:
            by.setdefault((r.body.get("gate"), aid), []).append(r)
    out = []
    for (gate, aid), rs in by.items():
        cur = None
        for r in rs:
            at = datetime.fromisoformat(r.created_at.replace("Z", "+00:00"))
            if cur and at - cur["_end"] <= timedelta(minutes=gap_min):
                cur["_end"], cur["count"], cur["lastSeq"] = at, cur["count"] + 1, r.seq
                cur["verdicts"][r.body.get("verdict")] = cur["verdicts"].get(r.body.get("verdict"), 0) + 1
                continue
            cur = {"gate": gate, "agent": aid, "_start": at, "_end": at, "count": 1, "firstSeq": r.seq, "lastSeq": r.seq,
                   "verdicts": {r.body.get("verdict"): 1}}
            out.append(cur)
    now = utcnow()
    for e in out:
        e["start"], e["end"] = _iso(e.pop("_start")), _iso(e["_end"])
        e["active"] = now - e.pop("_end") <= timedelta(minutes=ACTIVE_MIN)
    return sorted(out, key=lambda e: e["start"], reverse=True)


def status(s: Session, tenant: str | None) -> dict:
    """상단 바 관문 칩 — p95·예산 + 강등 중이면 closed(적)·open(주황)."""
    since = utcnow() - timedelta(minutes=ACTIVE_MIN)
    recs = _gate_records(s, tenant, since)
    modes = {a.id: a.fail_mode for a in s.scalars(select(models.Agent))}
    out = {}
    for g in ("input", "tool", "output"):
        rs = [r for r in recs if r.body.get("gate") == g]
        lat = [float(r.body.get("latencyMs", 0)) for r in rs]
        budget = orchestrator.GATE_BUDGET_MS[g]
        degraded = sorted({a for r in rs for a in r.body.get("degraded") or []})
        p95 = _q(lat, 0.95)
        mode = ("closed" if any(modes.get(a) == "closed" for a in degraded) else "open") if degraded else None
        out[g] = {"p95": p95, "budget": budget, "records": len(rs), "degraded": degraded, "mode": mode,
                  "status": mode and f"degraded-{mode}" or ("none" if not rs else "over" if p95 > budget else "near" if p95 >= 0.9 * budget else "ok")}
    return {"tenant": tenant or "*", "windowMin": ACTIVE_MIN, "gates": out,
            "degraded": [{"gate": g, "agents": v["degraded"], "mode": v["mode"]} for g, v in out.items() if v["degraded"]]}


def degradation(s: Session, tenant: str | None, days: int = 7) -> dict:
    from app import evidence_writer, sandbox
    from app.core.config import settings
    now = utcnow()
    recs = [r for r in _gate_records(s, tenant, now - timedelta(days=days)) if r.body.get("degraded")]
    eps = _episodes(recs)
    agents = {a.id: a for a in s.scalars(select(models.Agent).order_by(models.Agent.id))}
    calls: dict[str, int] = {}
    fq = select(models.Finding.agent_id, models.Finding.degraded).where(models.Finding.occurred_at >= now - timedelta(minutes=ACTIVE_MIN))
    if tenant:
        fq = fq.where(models.Finding.tenant == tenant)
    timeouts: dict[str, int] = {}
    for aid, d in s.execute(fq.limit(SCAN_LIMIT)):
        calls[aid] = calls.get(aid, 0) + 1
        timeouts[aid] = timeouts.get(aid, 0) + bool(d)
    current = []
    for e in eps:
        if not e["active"]:
            continue
        a = agents.get(e["agent"])
        mode = a.fail_mode if a else "closed"
        current.append(e | {"nameKo": a.name_ko if a else None, "name": a.name if a else None, "failMode": mode,
                            "effect": "차단 중(fail-closed)" if mode == "closed" else "통과 + 경보(fail-open)",
                            "timeoutRate": round(timeouts.get(e["agent"], 0) / calls[e["agent"]], 4) if calls.get(e["agent"]) else None})
    fpb = quality.fp_budget(s, tenant=tenant)["agents"]
    alert_only = [r for r in fpb if r["agentStatus"] == "alert_only" or r["status"] in ("warn", "exceeded")]
    for a in agents.values():                                   # 예산 표에 없는(오늘 판정 없는) 강등 에이전트도 보인다
        if a.status == "alert_only" and a.id not in {r["agent"] for r in alert_only}:
            alert_only.append({"agent": a.id, "nameKo": a.name_ko, "name": a.name, "gate": a.gate, "status": "alert_only",
                               "agentStatus": a.status, "consumed": None, "recovery": None})
    inline_open = [a.id for a in agents.values() if a.series in ("C1", "C2") and a.fail_mode == "open"]
    ew = evidence_writer.STATS
    sb = sandbox.status()
    l1 = next((p for p in sb["pools"] if p["level"] == "L1"), {})
    pol = policy.latest(s, "default", tenant or "default")
    pol_ref = f"{pol.policy_id}@v{pol.version}" if pol else None
    components = [
        {"id": "inline", "name": "인라인 타임아웃", "default": "C1·C2 차단 · C3·C4 통과 + 강등 증적",
         "now": f"강등 {len(current)}건" if current else "정상", "ok": not current, "metrics": {"degraded": len(current)}},
        {"id": "pdp", "name": "정책 결정점 장애", "default": "마지막 정책 스냅샷(관문 캐시)으로 로컬 판정",
         "now": f"정상 · {pol_ref}" if pol else "내장 기본 정책", "ok": True, "metrics": {"policy": pol_ref}},
        {"id": "ledger", "name": "증적 원장 장애", "default": "처리 계속 · 로컬 대기열(버퍼) 후 묶음 재적재 · 포화 시 allow 표본 적재",
         "now": ("표본 적재(강등) 중" if ew.get("degraded") else f"정상 · 실패 {ew.get('failed', 0)} · 버림 {ew.get('dropped', 0)}"),
         "ok": not ew.get("degraded") and not ew.get("failed"),
         "metrics": {"sampling": bool(ew.get("degraded")), "failed": ew.get("failed", 0), "dropped": ew.get("dropped", 0)}},
        {"id": "registry", "name": "레지스트리 장애", "default": "기존 바인딩 유지 · 신규 등록만 중단", "now": "정상", "ok": True, "metrics": {}},
        {"id": "sandbox", "name": "샌드박스 고갈", "default": "대기열 → 대기 시간 초과 시 호출 거부 · 격리 등급 낮춤 없음",
         "now": f"L1 대기 {l1.get('queued', 0)} · 거부 {l1.get('rejected', 0)}" if l1.get("available") else "L1 런타임 없음 — L1 에이전트 보류",
         "ok": not l1.get("rejected"), "metrics": {"l1": bool(l1.get("available")), "queued": l1.get("queued", 0), "rejected": l1.get("rejected", 0)}},
    ]
    return {"tenant": tenant or "*", "days": days, "activeWindowMin": ACTIVE_MIN, "current": current,
            "alertOnly": alert_only, "episodes": eps[:100],
            "failModes": [{"id": a.id, "name": a.name, "nameKo": a.name_ko, "series": a.series, "gate": a.gate, "failMode": a.fail_mode,
                           "timeoutMs": round(orchestrator.timeout_s(a.gate) * 1000) if orchestrator.timeout_s(a.gate) else None,
                           "status": a.status} for a in agents.values()],
            "dp5": {"rule": "인라인 계열(C1·C2)을 fail-open 으로 두면 누락 검증(FR-P16) 빌드 실패 — failMode 변경은 에이전트 새 버전 등록으로만",
                    "violations": inline_open},
            "components": components,
            "autoRules": {"warnAt": quality.WARN_AT, "demoteAt": 1.0, "recoverDays": settings.fp_recover_days,
                          "recoverRate": quality.FP_RATE, "budgetMin": settings.fp_budget_min,
                          "recoverBy": "자동(worker, 7일 오탐률 ≤ 0.5%) — 원장 quality fp_budget_restored"},
            "isolation": "격리 등급을 낮추는 강등은 어떤 경우에도 없음 (MSG-006)"}


def slo_check(s: Session, by: str = "worker") -> list[dict]:
    """비용·SLO 경보 (SCR-D02 ⑧, X10) — 테넌트·인라인 관문별 경보를 모아 원장(slo)에 남긴다 → 알림 센터."""
    out = []
    for t in list(s.scalars(select(models.Tenant.id))):
        mine = [{"tenant": t, "gate": g} | a for g in policy.INLINE_GATES for a in detail(s, t, g, 24)["alerts"]]
        ledger.append(s, "slo", "check", {"event": "slo_checked", "alerts": mine, "by": by}, t)   # 테넌트 원장 — 최신 기록이 이전 경보를 대체
        out += mine
    return out
