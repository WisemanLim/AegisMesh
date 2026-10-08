"""도메인 상세 화면 집계 (SCR-E02~M04) — 판정·원장·정책 이력에서 화면별 표를 만든다. 원문은 저장돼 있지 않으므로
판정 근거(위치·길이·유형)와 판정 기록의 요청 모양(gating.shape)만 쓴다(NFR-D1)."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.schemas import JudgeRequest, MemoryRecord, Principal, RetrievedDoc, Subject
from app import ledger, models, orchestrator, policy, registry

LIMIT = 2000


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def findings(s: Session, tenant: str | None, agents: list[str], hours: int = 24 * 7, limit: int = 200,
             rules: list[str] | None = None) -> list[models.Finding]:
    q = select(models.Finding).where(models.Finding.agent_id.in_(agents), models.Finding.occurred_at >= utcnow() - timedelta(hours=hours))
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    if rules:
        q = q.where(models.Finding.rule_id.in_(rules))
    return list(s.scalars(q.order_by(models.Finding.occurred_at.desc()).limit(limit)))


def finding_row(f: models.Finding) -> dict:
    b = f.body
    return {"id": f.id, "traceId": f.trace_id, "agent": f.agent_id, "verdict": f.verdict, "effective": b.get("effectiveVerdict"),
            "ruleId": f.rule_id, "confidence": f.confidence, "severity": f.severity, "at": f.occurred_at.isoformat(),
            "tenant": f.tenant, "principal": ((b.get("subject") or {}).get("principal") or {}).get("id"),
            "onBehalfOf": ((b.get("subject") or {}).get("onBehalfOf") or {}).get("id"),
            "evidence": b.get("evidence", [])}


def counts(s: Session, tenant: str | None, agents: list[str], hours: int = 24) -> dict[str, int]:
    q = select(models.Finding.rule_id, func.count()).where(models.Finding.agent_id.in_(agents),
                                                           models.Finding.occurred_at >= utcnow() - timedelta(hours=hours))
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    return dict(s.execute(q.group_by(models.Finding.rule_id)).all())


def gate_shapes(s: Session, tenant: str | None, traces: list[str]) -> dict[str, dict]:
    """trace → 판정 기록(원장 gate)의 요청 모양·판정."""
    if not traces:
        return {}
    q = select(models.Evidence).where(models.Evidence.kind == "gate", models.Evidence.ref_id.in_(traces))
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    return {r.ref_id: r.body for r in s.scalars(q)}


# ── SCR-E02 입력 검사 뷰어 ─────────────────────────────────────
def inspect_finding(s: Session, tenant: str | None, fid: str) -> dict | None:
    q = select(models.Finding).where(models.Finding.id == fid)
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    f = s.scalars(q).first()
    if f is None:
        return None
    gate = gate_shapes(s, tenant, [f.trace_id]).get(f.trace_id) or {}
    shape = gate.get("shape") or {}
    ev = f.body.get("evidence", [])
    segs = []
    for g in shape.get("segments", []):
        hits = [e for e in ev if e.get("location") == f"segments[{g['i']}]"]
        segs.append(g | {"hits": hits, "authority": "데이터 전용 «»" if g["trust"] == "untrusted" else "지시 권한"})
    siblings = list(s.scalars(select(models.Finding).where(models.Finding.trace_id == f.trace_id, models.Finding.id != f.id)))
    return {"finding": finding_row(f) | {"body": f.body, "gate": f.gate, "valid": f.valid, "degraded": f.degraded},
            "shape": shape, "segments": segs, "gateVerdict": gate.get("verdict"), "target": gate.get("profile"),
            "siblings": [finding_row(x) for x in siblings],
            "raw": "원문 미보존 — 근거 구간(위치·길이)과 요청 모양만. 원문 재검사는 붙여 넣은 입력으로(저장 없음)"}


# ── SCR-E04 유출 차단 ─────────────────────────────────────────
def provenance(s: Session, tenant: str, agent: str, key: str, policy_id: str = "default") -> list[dict]:
    """목록 설정 값마다 처음 들어온 정책 버전·작성자·시각 (현재 값 기준)."""
    seen: dict[str, dict] = {}
    for p in reversed(policy.versions(s, policy_id, tenant)):          # 오래된 것부터
        vals = (((p.body.get("spec") or {}).get("agentParams") or {}).get(agent) or {}).get(key) or []
        vals = [str(v) for v in vals] if isinstance(vals, list) else []
        for v in list(seen):
            if v not in vals:
                seen.pop(v)
        for v in vals:
            seen.setdefault(v, {"value": v, "version": p.version, "by": p.created_by, "at": p.created_at.isoformat()})
    return list(seen.values())


def exfil(s: Session, tenant: str) -> dict:
    c6, c7 = counts(s, tenant, ["d1-06"]), counts(s, tenant, ["d1-07"])
    design = []
    for f in findings(s, tenant, ["d1-07", "d2-03"], hours=24 * 7, limit=500):
        locs = [e.get("location") for e in f.body.get("evidence", [])]
        if f.rule_id == "D1-07.secret-in-context" or (f.agent_id == "d2-03" and "system" in locs and f.verdict != "allow"):
            design.append(finding_row(f))
    by_target: dict[str, dict] = {}
    for r in design:
        k = r["principal"] or r["tenant"]
        x = by_target.setdefault(k, {"target": k, "count": 0, "last": r["at"], "finding": r["id"]})
        x["count"] += 1
    return {"tenant": tenant, "counts24h": {"d1-06": c6, "d1-07": c7},
            "canaryHits24h": c7.get("D1-07.canary", 0),
            "allowlist": provenance(s, tenant, "d1-06", "urlAllowlist"),
            "canaries": [{"token": (v["value"][:6] + "…" + v["value"][-2:]) if len(v["value"]) > 10 else "●" * len(v["value"]),
                          "version": v["version"], "by": v["by"], "at": v["at"]} for v in provenance(s, tenant, "d1-07", "canaries")],
            "designViolations": sorted(by_target.values(), key=lambda x: -x["count"]),
            "principle": "비밀(API 키·비밀번호·접속 문자열)은 시스템 지시·도구 스키마에 두지 않는다 — 비밀 브로커 임대 참조로"}


# ── SCR-F03 세션 격리·자격증명·무단 접근 ─────────────────────────
def access_decisions(s: Session, tenant: str | None, limit: int = 50) -> list[dict]:
    fs = findings(s, tenant, ["d2-04"], hours=24 * 7, limit=limit)
    shapes = gate_shapes(s, tenant, [f.trace_id for f in fs])
    rows = []
    for f in fs:
        r = finding_row(f)
        denied = {e["location"].split(":", 1)[1] for e in r["evidence"] if (e.get("location") or "").startswith("retrieval:")}
        docs = (shapes.get(f.trace_id, {}).get("shape") or {}).get("retrieval") or [{"id": d} for d in sorted(denied)]
        for d in docs:
            rows.append({"at": r["at"], "traceId": r["traceId"], "principal": r["principal"], "agent": r["onBehalfOf"],
                         "doc": d["id"], "acl": d.get("acl"), "postCheck": "deny" if d["id"] in denied else "allow",
                         "verdict": r["effective"] or r["verdict"], "finding": r["id"]})
    return rows


SECRET_LOC = {"text": "prompt", "system": "prompt", "output": "output"}


def secret_scan(s: Session, tenant: str | None, hours: int = 24) -> dict:
    by = {"prompt": 0, "output": 0, "log": 0}
    recent = []
    for f in findings(s, tenant, ["d2-03"], hours=hours, limit=LIMIT):
        if f.verdict == "allow":
            continue
        for e in f.body.get("evidence", []):
            loc = e.get("location") or ""
            by[SECRET_LOC.get(loc, "prompt" if loc.startswith("segments") else "output")] += 1
        if len(recent) < 20:
            recent.append(finding_row(f))
    for f in findings(s, tenant, ["d2-06"], hours=hours, limit=LIMIT):
        by["log"] += f.verdict != "allow"
    q = select(models.SecretLease)
    if tenant:
        q = q.where(models.SecretLease.tenant == tenant)
    leases = list(s.scalars(q))
    from app import secrets_broker
    st = [secrets_broker.state(r) for r in leases]
    return {"hours": hours, "byLocation": by, "recent": recent,
            "leases": {"active": st.count("active"), "revoked": st.count("revoked"), "expired": st.count("expired"), "total": len(st)},
            "note": "유출 키는 형태·위치만 기록(값 없음). 동적 임대 비밀은 즉시 폐기(비밀 브로커) — 정적 키는 임대로 전환 권고"}


def _probe(kind: str, tenant: str, other: str, i: int) -> JudgeRequest:
    me = Principal(id=f"probe-a{i}")
    if kind == "tenant":
        return JudgeRequest(subject=Subject(tenant=tenant, principal=me), retrieval=[RetrievedDoc(id=f"doc{i}", tenant=other, text="x")])
    if kind == "user":
        return JudgeRequest(subject=Subject(tenant=tenant, principal=me), retrieval=[RetrievedDoc(id=f"doc{i}", owner=f"probe-b{i}", text="x")])
    return JudgeRequest(subject=Subject(tenant=tenant, principal=me), session={"id": f"sx{i}"},
                        memory=[MemoryRecord(id=f"m{i}", session=f"sy{i}", owner=me.id, text="x")])


def cross_scope_regression(s: Session, tenant: str, by: str, n: int = 100) -> dict:
    """교차 조회 회귀 시험 — 테넌트·주체·세션 경계를 넘는 항목을 넣은 합성 요청 n 건씩을 D2-02 로 판정해 놓친 건(누출)을 센다.
    정책 설정 적용, 판정 저장 없음, 결과만 원장(isolation_regression)."""
    rt = registry.runtime_agent("d2-02")
    params = policy.spec_of(policy.latest(s, "default", tenant)).agent_params
    rows = []
    for kind, label in (("tenant", "테넌트 → 다른 테넌트 문서"), ("user", "주체 A → B 소유 문서"), ("session", "세션 X → Y 메모리")):
        missed = 0
        for i in range(n):
            req = orchestrator.agent_request(rt, _probe(kind, tenant, "__other__", i), params)
            missed += rt.judge(req).verdict == "allow"
        rows.append({"case": kind, "title": label, "probes": n, "leaked": missed, "ok": missed == 0})
    body = {"event": "isolation_regression", "cases": rows, "ok": all(r["ok"] for r in rows), "by": by}
    rec = ledger.append(s, "isolation", f"regress-{secrets.token_hex(4)}", body, tenant)
    return body | {"seq": rec.seq}


def isolation(s: Session, tenant: str) -> dict:
    last = s.scalars(select(models.Evidence).where(models.Evidence.kind == "isolation", models.Evidence.tenant == tenant)
                     .order_by(models.Evidence.seq.desc()).limit(1)).first()
    plat = s.scalars(select(models.Evidence).where(models.Evidence.kind == "tenancy").order_by(models.Evidence.seq.desc()).limit(1)).first()
    params = policy.spec_of(policy.latest(s, "default", tenant)).agent_params.get("d2-02", {})
    return {"tenant": tenant, "counts24h": counts(s, tenant, ["d2-02", "d2-03", "d2-04"]),
            "sessionScopedMemory": params.get("sessionScopedMemory", True),
            "regression": (last.body | {"at": last.created_at, "seq": last.seq}) if last else None,
            "platformIsolation": ({k: plat.body.get(k) for k in ("ok", "passed", "total", "failed")} | {"at": plat.created_at}) if plat else None,
            "secrets": secret_scan(s, tenant), "access": access_decisions(s, tenant)}


# ── SCR-G02 도구 호출 판정 상세 ────────────────────────────────
def _gate(s: Session, tenant: str | None, gate: str, limit: int) -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.kind == "gate")
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    rows = []
    for r in s.scalars(q.order_by(models.Evidence.seq.desc()).limit(limit * 6)):
        if r.body.get("gate") == gate:
            rows.append(r)
            if len(rows) >= limit:
                break
    return rows


def calls(s: Session, tenant: str | None, limit: int = 30) -> list[dict]:
    out = []
    for r in _gate(s, tenant, "tool", limit):
        b, sh = r.body, r.body.get("shape") or {}
        hits = [d for d in b.get("decisions", []) if d.get("effective") != "allow"]
        out.append({"traceId": r.ref_id, "at": r.created_at, "tool": (sh.get("tool") or {}).get("name"), "principal": sh.get("principal"),
                    "onBehalfOf": sh.get("onBehalfOf"), "verdict": b.get("verdict"), "rules": [d["ruleId"] for d in hits][:4],
                    "approvalRef": b.get("approvalRef"), "latencyMs": b.get("latencyMs")})
    return out


def call(s: Session, tenant: str | None, trace: str) -> dict | None:
    rec = gate_shapes(s, tenant, [trace]).get(trace)
    if rec is None or rec.get("gate") != "tool":
        return None
    q = select(models.Finding).where(models.Finding.trace_id == trace)
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    fs = [finding_row(f) | {"valid": f.valid} for f in s.scalars(q.order_by(models.Finding.agent_id))]
    apr = None
    if rec.get("approvalRef"):
        from app import approvals
        a = s.get(models.Approval, rec["approvalRef"])
        apr = approvals.out(s, a) if a is not None else None
    ev = s.scalars(select(models.Evidence).where(models.Evidence.kind == "gate", models.Evidence.ref_id == trace)).first()
    return {"traceId": trace, "gate": rec, "shape": rec.get("shape") or {}, "findings": fs, "approval": apr,
            "ledger": {"seq": ev.seq, "hash": ev.hash, "at": ev.created_at} if ev else None,
            "raw": "인자 원문 미보존 — 인자 이름·판정 근거(위치)만"}


# ── SCR-G03 샌드박스·파일 경로 ─────────────────────────────────
def d3_sandbox(s: Session, tenant: str | None) -> dict:
    from app import sandbox
    st = sandbox.status()
    avail = {p["level"]: p["available"] for p in st["pools"]}
    agents = [{"id": a.id, "name": a.name, "nameKo": a.name_ko, "gate": a.gate, "required": a.isolation,
               "runnable": avail.get(a.isolation, False), "status": a.status}
              for a in s.scalars(select(models.Agent).order_by(models.Agent.id))]
    ev = [finding_row(f) for f in findings(s, tenant, ["d3-03", "d3-04"], hours=24 * 7, limit=100) if f.verdict != "allow"][:20]
    return {"sandbox": st, "workloads": [a for a in agents if a["required"] != "L0"] or agents[:0],
            "levels": {lv: sum(a["required"] == lv for a in agents) for lv in ("L0", "L1", "L2", "L3")},
            "refused": [a for a in agents if not a["runnable"]], "events": ev}


# ── SCR-G04 쿼터·권한 상승·도구 레지스트리 ───────────────────────
def d3_registry(s: Session, tenant: str) -> dict:
    now = utcnow()
    use: dict[str, dict] = {}
    for r in _gate(s, tenant, "tool", LIMIT):
        sh = r.body.get("shape") or {}
        pid = sh.get("principal") or "—"
        at = datetime.fromisoformat(r.created_at.replace("Z", "+00:00"))
        u = use.setdefault(pid, {"principal": pid, "hour": 0, "day": 0, "blocked": 0})
        if now - at <= timedelta(hours=1):
            u["hour"] += 1
        if now - at <= timedelta(days=1):
            u["day"] += 1
            u["blocked"] += r.body.get("verdict") == "block"
    spec = policy.spec_of(policy.latest(s, "default", tenant))
    quotas = spec.agent_params.get("d3-05", {}).get("quotas") or {}
    for pid, u in use.items():
        q = quotas.get(pid) or quotas.get("*") or {}
        u["quota"] = q
        lim = q.get("perDay")
        u["state"] = "over" if lim and u["day"] >= lim else "near" if lim and u["day"] >= 0.9 * lim else "ok"
    allow = spec.agent_params.get("d3-07", {}).get("toolAllowlist")
    tq = select(models.ScanTarget).where(models.ScanTarget.kind.in_(("tool", "mcp_server", "plugin", "skill")))
    qq = select(models.Quarantine).where(models.Quarantine.active.is_(True)) if hasattr(models.Quarantine, "active") else select(models.Quarantine)
    if tenant:
        tq, qq = tq.where(models.ScanTarget.tenant == tenant), qq.where(models.Quarantine.tenant == tenant)
    quarantined = {(q.kind, q.value) for q in s.scalars(qq)}
    tools = [{"name": t.name, "kind": t.kind, "lastVerdict": t.last_verdict, "lastRunAt": t.last_run_at.isoformat() if t.last_run_at else None,
              "pinned": bool((t.artifact or {}).get("pinnedToolsHash") or (t.artifact or {}).get("toolsHash")),
              "quarantined": (t.kind, t.name) in quarantined, "allowlisted": None if allow is None else t.name in allow}
             for t in s.scalars(tq)]
    names = sorted(set(allow or []) | {t["name"] for t in tools})
    rt = registry.runtime_agent("d3-06")
    paths = rt.engines[rt.manifest.spec.engines.default].module.escalation_paths(names)
    blocked = set(spec.agent_params.get("d3-06", {}).get("blockedChains") or [])
    for x in paths:
        x["blocked"] = f"{x['from']}->{x['to']}" in blocked
    return {"tenant": tenant, "usage": sorted(use.values(), key=lambda u: -u["day"])[:50], "quotas": quotas,
            "allowlist": allow, "tools": tools, "escalation": paths[:50],
            "scopeFindings": [finding_row(f) for f in findings(s, tenant, ["d3-06"], hours=24 * 7, limit=30) if f.verdict != "allow"],
            "unregistered": [finding_row(f) for f in findings(s, tenant, ["d3-07"], hours=24 * 7, limit=30) if f.verdict != "allow"]}


# ── SCR-H02·H03·H04 ─────────────────────────────────────────
def d4_grounding(s: Session, tenant: str | None, fid: str) -> dict | None:
    out = inspect_finding(s, tenant, fid)
    if out is None:
        return None
    sib = {x["agent"]: x for x in out["siblings"]}
    me = out["finding"]
    return out | {"citation": sib.get("d4-02") or (me if me["agent"] == "d4-02" else None), "retrieval": out["shape"].get("retrieval") or []}


def d4_decisions(s: Session, tenant: str | None) -> dict:
    fs = findings(s, tenant, ["d4-03"], hours=24 * 7, limit=100)
    q = select(models.Approval).where(models.Approval.trace_id.in_([f.trace_id for f in fs])) if fs else None
    aprs = {a.trace_id: a for a in s.scalars(q)} if q is not None else {}
    rows = []
    for f in fs:
        if f.verdict == "allow":
            continue
        a = aprs.get(f.trace_id)
        rows.append(finding_row(f) | {"approval": {"id": a.id, "status": a.status} if a else None})
    return {"lowConfidence": rows[:30], "counts7d": counts(s, tenant, ["d4-03", "d4-04", "d4-05"], hours=24 * 7)}


def _labels(s: Session, tenant: str | None, agents: list[str], since: datetime) -> list[models.FindingLabel]:
    q = select(models.FindingLabel).where(models.FindingLabel.agent_id.in_(agents), models.FindingLabel.requested_at >= since)
    if tenant:
        q = q.where(models.FindingLabel.tenant == tenant)
    return list(s.scalars(q.order_by(models.FindingLabel.requested_at.desc())))


def _rate(s: Session, tenant: str | None, agent: str, start: datetime, end: datetime) -> tuple[int, int]:
    q = select(models.Finding.verdict).where(models.Finding.agent_id == agent, models.Finding.occurred_at >= start, models.Finding.occurred_at < end)
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    vs = list(s.scalars(q.limit(LIMIT * 10)))
    return sum(v != "allow" for v in vs), len(vs)


def correction_log(s: Session, tenant: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in s.scalars(select(models.Evidence).where(models.Evidence.kind == "correction", models.Evidence.tenant == tenant).order_by(models.Evidence.seq)):
        out[r.ref_id] = r.body | {"at": r.created_at, "seq": r.seq}
    return out


def d4_propagation(s: Session, tenant: str) -> dict:
    fs = findings(s, tenant, ["d4-06"], hours=24 * 30, limit=300)
    shapes = gate_shapes(s, tenant, [f.trace_id for f in fs])
    corr = correction_log(s, tenant)
    sources: dict[str, dict] = {}
    for f in fs:
        sh = (shapes.get(f.trace_id) or {}).get("shape") or {}
        src = sh.get("provenance") or "출처 미표기"
        node = sources.setdefault(src, {"source": src, "points": []})
        c = corr.get(f.trace_id)
        node["points"].append({"traceId": f.trace_id, "finding": f.id, "destination": sh.get("destination") or "user", "at": f.occurred_at.isoformat(),
                               "verdict": f.body.get("effectiveVerdict") or f.verdict, "ruleId": f.rule_id,
                               "status": (c or {}).get("status") or ("gate_blocked" if (f.body.get("effectiveVerdict") or f.verdict) == "block" else "pending"),
                               "correctedAt": (c or {}).get("at")})
    now = utcnow()
    cur, prev = (now - timedelta(days=7), now), (now - timedelta(days=14), now - timedelta(days=7))
    g1, n1 = _rate(s, tenant, "d4-01", *cur)
    g0, n0 = _rate(s, tenant, "d4-01", *prev)
    labels = _labels(s, tenant, [f"d4-0{i}" for i in range(1, 8)], now - timedelta(days=14))
    neg1 = sum((lb.requested_at if lb.requested_at.tzinfo else lb.requested_at.replace(tzinfo=timezone.utc)) >= cur[0] for lb in labels)
    j1 = sum(_rate(s, tenant, f"d4-0{i}", *cur)[1] for i in (1, 2, 5))
    o1, k1 = _rate(s, tenant, "d4-07", *cur)
    recur = 0                                   # 정정 완료 뒤 같은 출처에서 다시 퍼진 지점
    for src in sources.values():
        fixed = min((p["correctedAt"] for p in src["points"] if p["status"] == "corrected" and p["correctedAt"]), default=None)
        if fixed:
            recur += sum(p["at"] > fixed.replace("Z", "+00:00") and p["status"] != "corrected" for p in src["points"])
    metrics = {"groundedness": round(1 - g1 / n1, 3) if n1 else None, "groundednessPrev": round(1 - g0 / n0, 3) if n0 else None,
               "negativeFeedback": round(neg1 / j1, 4) if j1 else None, "uncertaintyMissing": round(o1 / k1, 4) if k1 else None,
               "recurrence": recur}
    alerts = []
    if metrics["groundedness"] is not None and metrics["groundednessPrev"] is not None and metrics["groundedness"] < metrics["groundednessPrev"] - 0.05:
        alerts.append(f"근거성 점수 {metrics['groundedness']} (전주 {metrics['groundednessPrev']}) — 회귀")
    top = sorted(sources.values(), key=lambda x: -len(x["points"]))[:20]
    for x in top:                                  # 출처당 최근 20 지점만(전체 수는 total)
        x["total"] = len(x["points"])
        x["points"] = x["points"][:20]
    return {"tenant": tenant, "sources": top, "metrics": metrics, "alerts": alerts,
            "feedback": [{"finding": lb.finding_id, "agent": lb.agent_id, "reason": lb.reason, "detail": lb.detail, "status": lb.status,
                          "label": lb.label, "at": lb.requested_at.isoformat()} for lb in labels[:20]]}


CORRECTION = ("quarantined", "corrected", "gate_blocked", "requested", "pending")


def correct(s: Session, tenant: str, trace: str, status: str, by: str, note: str = "") -> dict:
    if status not in CORRECTION:
        raise ValueError(f"상태 {CORRECTION}")
    rec = ledger.append(s, "correction", trace, {"event": "correction", "status": status, "note": note[:200], "by": by}, tenant)
    return {"traceId": trace, "status": status, "seq": rec.seq}


def retro_correct(s: Session, tenant: str, source: str, by: str) -> dict:
    """소급 정정 — 출처에서 퍼진 지점 중 정정 완료가 아닌 것에 정정 요청을 원장에 남긴다(추가 전용, 실패만 재시도)."""
    src = next((x for x in d4_propagation(s, tenant)["sources"] if x["source"] == source), None)
    if src is None:
        raise KeyError(source)
    done = []
    for p in src["points"]:
        if p["status"] not in ("corrected", "gate_blocked"):
            done.append(correct(s, tenant, p["traceId"], "requested", by, f"소급 정정 — 출처 {source}"))
    return {"source": source, "requested": len(done), "skipped": len(src["points"]) - len(done)}


# ── D5 접근 통제 (SCR-I02·I03·I04) ──────────────────────────────
def _all_gate(s: Session, tenant: str | None, hours: int, limit: int = LIMIT) -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.kind == "gate",
                                      models.Evidence.created_at >= (utcnow() - timedelta(hours=hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    return list(s.scalars(q.order_by(models.Evidence.seq.desc()).limit(limit)))


def _worst(fs: list[dict]) -> str:
    from aegis.schemas import VERDICT_RANK
    return max((f.get("effective") or f["verdict"] for f in fs), key=VERDICT_RANK.__getitem__, default="allow")


def d5_identity(s: Session, tenant: str | None, with_svids: bool) -> dict:
    from app import identity
    svids = None
    if with_svids:
        st = identity.status(s)
        svids = {k: st[k] for k in ("trustDomain", "ttlSec", "rotateAt", "counts", "valid", "expired", "revoked", "nextRotation", "lastRotation")} | {
            "items": [x for x in st["items"] if not tenant or x["tenant"] in (None, tenant)][:80]}
    cards = [finding_row(f) for f in findings(s, tenant, ["x01", "d5-04"], hours=24 * 7, limit=100) if f.verdict != "allow"]
    trusted = policy.spec_of(policy.latest(s, "default", tenant or "default")).agent_params.get("x01", {}).get("trustedKeys") or {}
    bind: dict[tuple, dict] = {}
    for r in _gate(s, tenant, "tool", 500):
        sh = r.body.get("shape") or {}
        tool = (sh.get("tool") or {}).get("name")
        if not tool or not sh.get("principal"):
            continue
        out_of_bind = [d["ruleId"] for d in r.body.get("decisions", []) if d.get("effective") != "allow" and
                       any(d["ruleId"].startswith(x) for x in ("D3-07.not-allowlisted", "D6-04.tool-out-of-scope", "D3-06.scope-exceeded"))]
        x = bind.setdefault((sh["principal"], tool), {"principal": sh["principal"], "tool": tool, "calls": 0, "blocked": 0, "rules": set()})
        x["calls"] += 1
        x["blocked"] += bool(out_of_bind)
        x["rules"] |= set(out_of_bind)
    return {"svids": svids, "static": identity.static_credentials(s, tenant), "leases": secret_scan(s, tenant)["leases"],
            "cards": cards[:30], "trustedKeys": sorted(trusted),
            "binding": [v | {"rules": sorted(v["rules"])} for v in sorted(bind.values(), key=lambda v: (-v["blocked"], v["principal"]))][:60]}


def d5_tokens(s: Session, tenant: str | None, hours: int = 24) -> dict:
    recs = [r for r in _all_gate(s, tenant, hours) if (r.body.get("shape") or {}).get("auth")]
    toks: dict[str, dict] = {}
    for r in recs:
        sh = r.body["shape"]
        a, sm = sh["auth"], sh.get("sessionMeta") or {}
        key = a.get("jti") or f"{sh.get('principal')}|{','.join(a.get('aud') or [])}|{a.get('method')}"
        t = toks.setdefault(key, {"token": a.get("jti"), "principal": sh.get("principal"), "method": a.get("method"),
                                  "binding": a.get("cnf") or ("session" if sm.get("bound") else "bearer"), "aud": a.get("aud") or [],
                                  "lifetimeSec": a.get("lifetimeSec"), "uses": 0, "ips": set(), "sessions": set(), "traces": [],
                                  "first": r.created_at, "last": r.created_at})
        t["uses"] += 1
        t["first"] = min(t["first"], r.created_at)
        if sm.get("ip"):
            t["ips"].add(sm["ip"])
        if sh.get("session"):
            t["sessions"].add(sh["session"])
        t["traces"].append(r.ref_id)
    fs = {}
    q = select(models.Finding).where(models.Finding.agent_id.in_(["d5-03", "d5-06"]),
                                     models.Finding.trace_id.in_([x for t in toks.values() for x in t["traces"]][:5000]))
    for f in (s.scalars(q) if toks else []):
        fs.setdefault(f.trace_id, []).append(finding_row(f))
    rows, events = [], []
    for t in toks.values():
        mine = [x for tr in t["traces"] for x in fs.get(tr, [])]
        reuse = t["token"] is not None and (len(t["ips"]) > 1 or len(t["sessions"]) > 1)
        status = "reuse" if reuse else _worst(mine)
        rows.append({k: v for k, v in t.items() if k not in ("ips", "sessions", "traces")} | {"nodes": len(t["ips"]), "sessions": len(t["sessions"]),
                                                                                             "status": status, "rules": sorted({x["ruleId"] for x in mine if x["verdict"] != "allow"})})
        if reuse:
            events.append({"kind": "reuse", "token": t["token"], "principal": t["principal"], "at": t["last"], "nodes": len(t["ips"]),
                           "sessions": len(t["sessions"]), "note": f"같은 토큰이 노드 {len(t['ips'])}곳·세션 {len(t['sessions'])}개에서 사용"})
    for f in findings(s, tenant, ["d5-03", "d5-06"], hours=hours, limit=200):
        if f.verdict != "allow":
            r = finding_row(f)
            events.append({"kind": f.rule_id.split(".")[1], "token": None, "principal": r["principal"], "at": r["at"], "verdict": r["effective"] or r["verdict"],
                           "note": "; ".join(e["note"] for e in r["evidence"]), "finding": r["id"]})
    bound = [x for x in rows if x["binding"] in ("dpop", "mtls", "session")]
    life = [x["lifetimeSec"] for x in rows if x["lifetimeSec"]]
    return {"hours": hours, "kpi": {"tokens": len(rows), "avgLifetimeSec": round(sum(life) / len(life)) if life else None,
                                    "boundRatio": round(len(bound) / len(rows), 3) if rows else None,
                                    "byBinding": {b: sum(x["binding"] == b for x in rows) for b in ("dpop", "mtls", "session", "bearer")},
                                    "anomalies": sum(e["kind"] in ("fingerprint-mismatch", "ip-change") for e in events),
                                    "reuse": sum(e["kind"] in ("reuse", "audience-mismatch", "client-mismatch") for e in events)},
            "tokens": sorted(rows, key=lambda x: x["last"], reverse=True)[:80], "events": sorted(events, key=lambda e: e["at"], reverse=True)[:40],
            "note": "토큰 원문·IP 는 저장하지 않는다 — jti·IP·장치 지문은 해시 앞 8자로만 대조"}


def _drift(s: Session, tenant: str | None, days: int = 30) -> list[dict]:
    per: dict[str, dict] = {}
    for r in _all_gate(s, tenant, 24 * days):
        sh = r.body.get("shape") or {}
        for who, meta in (("principal", sh.get("principalMeta")), ("onBehalfOf", sh.get("agentMeta"))):
            pid = sh.get(who)
            if not pid or not meta:
                continue
            x = per.setdefault(pid, {"id": pid, "type": meta.get("type"), "granted": set(), "used": set(), "calls": 0})
            x["granted"] |= set(meta.get("scopes") or [])
            if who == "principal":
                x["calls"] += 1
            if r.body.get("verdict") in ("allow", "alert", "transform") or r.body.get("approvalRef"):
                x["used"] |= set((sh.get("tool") or {}).get("requiredScopes") or [])
    return [{"id": x["id"], "type": x["type"], "granted": sorted(x["granted"]), "used": sorted(x["used"] & x["granted"]),
             "unused": sorted(x["granted"] - x["used"]), "calls": x["calls"]} for x in per.values() if x["granted"]]


def d5_authz(s: Session, tenant: str) -> dict:
    pol = policy.latest(s, "default", tenant)
    tests = len((pol.body.get("tests") or [])) if pol else 0
    dec = []
    shapes = {}
    fs = findings(s, tenant, ["d5-02"], hours=24 * 7, limit=60)
    shapes = gate_shapes(s, tenant, [f.trace_id for f in fs])
    for f in fs:
        r, sh = finding_row(f), (shapes.get(f.trace_id) or {}).get("shape") or {}
        dec.append({"at": r["at"], "principal": r["principal"], "agent": r["onBehalfOf"], "action": (sh.get("tool") or {}).get("name") or (sh.get("action") or {}).get("type"),
                    "resource": sh.get("resource"), "verdict": r["effective"] or r["verdict"], "ruleId": r["ruleId"], "finding": r["id"]})
    deleg = []
    for r in _gate(s, tenant, "tool", 300):
        sh = r.body.get("shape") or {}
        if not sh.get("onBehalfOf") or not sh.get("principalMeta"):
            continue
        hs, ag = set(sh["principalMeta"].get("scopes") or []), set((sh.get("agentMeta") or {}).get("scopes") or [])
        need = set((sh.get("tool") or {}).get("requiredScopes") or [])
        deleg.append({"at": r.created_at, "traceId": r.ref_id, "principal": sh["principal"], "agent": sh["onBehalfOf"], "effective": sorted(hs & ag),
                      "requested": sorted(need), "outside": sorted(need - (hs & ag)), "verdict": r.body.get("verdict")})
    drift = _drift(s, tenant)
    return {"tenant": tenant, "pdp": {"engine": "내장 선언형 정책 평가기(결정 인터페이스 분리 — OPA·OpenFGA·Cerbos 교체 가능)",
                                      "policy": f"{pol.policy_id}@v{pol.version}" if pol else None, "unitTests": tests},
            "decisions": dec, "delegation": deleg[:40], "drift": sorted(drift, key=lambda x: -len(x["unused"]))[:40]}


def drift_scan(s: Session, tenant: str, by: str) -> dict:
    """실사용 권한 수집(관문 기록) → 권한 인벤토리 → D5-07 상시 점검 경로로 판정(원장·Finding)."""
    from app import scanner
    inv = [{"id": x["id"], "type": x["type"], "granted": x["granted"], "used": x["used"]} for x in _drift(s, tenant)]
    r = scanner.run_scan(s, {"kind": "permission_inventory", "name": f"observed-{tenant}", "principals": inv}, tenant, agent_ids=["d5-07"], by=by)
    return {"principals": len(inv), "verdict": r["verdict"], "hits": r["hits"], "traceId": r["traceId"]}


# ── D6 자율 과잉 (SCR-J02·J03·J04) ──────────────────────────────
def _contracts(s: Session, tenant: str) -> dict:
    ap = policy.spec_of(policy.latest(s, "default", tenant)).agent_params
    return {a: (ap.get(a) or {}) for a in ("d6-01", "d6-04", "d6-05", "d6-06", "d6-07", "d6-02", "d6-03")}


def d6_autonomy(s: Session, tenant: str, target: str | None) -> dict:
    con = _contracts(s, tenant)
    targets = {p for a in con.values() for p in (a.get("byPrincipal") or {})}
    ext_unapproved, ext = 0, 0
    for r in _gate(s, tenant, "tool", 1000):
        sh = r.body.get("shape") or {}
        if sh.get("principal"):
            targets.add(sh["principal"])
        act = sh.get("action") or {}
        if act.get("external") and (not target or sh.get("principal") == target):
            at = datetime.fromisoformat(r.created_at.replace("Z", "+00:00"))
            if utcnow() - at <= timedelta(days=1):
                ext += 1
                ext_unapproved += r.body.get("verdict") in ("allow", "alert") and not act.get("approved")
    def mine(agent):
        rows = [finding_row(f) for f in findings(s, tenant, [agent], hours=24, limit=200) if f.verdict != "allow"]
        return [x for x in rows if not target or x["principal"] == target]
    camp = s.scalars(select(models.Evidence).where(models.Evidence.kind == "redteam").order_by(models.Evidence.seq.desc()).limit(1)).first()
    align = {x["agent"]: x for x in (camp.body.get("results") or [])} if camp else {}
    return {"tenant": tenant, "target": target, "targets": sorted(targets),
            "contract": {a: ((c.get("byPrincipal") or {}).get(target) if target else None) for a, c in con.items()},
            "base": {a: {k: v for k, v in c.items() if k != "byPrincipal"} for a, c in con.items()},
            "external24h": ext, "externalUnapproved24h": ext_unapproved,
            "scopeBlocks": mine("d6-04")[:20], "means": mine("d6-05")[:20], "overAutonomy": mine("d6-01")[:20],
            "alignment": {a: align.get(a) for a in ("d6-01", "d6-04", "d6-05")}, "alignmentAt": camp.created_at if camp else None}


def d6_runs(s: Session, tenant: str | None, limit: int = 40) -> list[dict]:
    out = []
    for r in _gate(s, tenant, "tool", 600):
        b, sh = r.body, r.body.get("shape") or {}
        hits = [d for d in b.get("decisions", []) if d.get("agent") in ("d6-02", "d6-03") and d.get("effective") != "allow"]
        if not hits and not sh.get("history"):
            continue
        out.append({"traceId": r.ref_id, "at": r.created_at, "principal": sh.get("principal"), "verdict": b.get("verdict"),
                    "steps": len(sh.get("history") or []), "depth": max((h.get("depth", 0) for h in sh.get("history") or []), default=0),
                    "rules": [d["ruleId"] for d in hits]})
        if len(out) >= limit:
            break
    return out


def d6_run(s: Session, tenant: str | None, trace: str) -> dict | None:
    c = call(s, tenant, trace)
    if c is None:
        return None
    sh = c["shape"]
    hist = sh.get("history") or []
    seen, states = set(), []
    for h in hist:
        if h.get("stateHash"):
            states.append({"hash": str(h["stateHash"])[:8], "repeat": h["stateHash"] in seen})
            seen.add(h["stateHash"])
    ap = policy.spec_of(policy.latest(s, "default", tenant or "default")).agent_params
    def eff(a):
        base = {k: v for k, v in (ap.get(a) or {}).items() if k != "byPrincipal"}
        return base | (((ap.get(a) or {}).get("byPrincipal") or {}).get(sh.get("principal")) or {})
    return c | {"nodes": [{k: h.get(k) for k in ("agent", "parent", "depth", "tool")} for h in hist], "states": states,
                "limits": {"d6-02": eff("d6-02"), "d6-03": eff("d6-03")}}


def d6_budgets(s: Session, tenant: str) -> dict:
    con = _contracts(s, tenant)
    today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    spend: dict[str, dict] = {}
    for r in _gate(s, tenant, "tool", 2000):
        sh = r.body.get("shape") or {}
        act = sh.get("action") or {}
        at = datetime.fromisoformat(r.created_at.replace("Z", "+00:00"))
        if act.get("amount") is None or at < today:
            continue
        x = spend.setdefault(sh.get("principal") or "—", {"principal": sh.get("principal") or "—", "executed": 0.0, "pending": 0.0, "blocked": 0.0, "count": 0})
        x["count"] += 1
        v = r.body.get("verdict")
        x["executed" if v in ("allow", "alert") else "pending" if v == "require_approval" else "blocked"] += float(act["amount"])
    fs = findings(s, tenant, ["d6-07"], hours=24 * 3, limit=200)
    aprs = {a.trace_id: a for a in s.scalars(select(models.Approval).where(models.Approval.trace_id.in_([f.trace_id for f in fs])))} if fs else {}
    from app import approvals as _ap
    cards = []
    for f in fs:
        a = aprs.get(f.trace_id)
        if a is not None and f.verdict == "require_approval":
            cards.append(finding_row(f) | {"approval": _ap.out(s, a)})
    quotas = [finding_row(f) for f in findings(s, tenant, ["d6-06"], hours=24, limit=100) if f.verdict != "allow"]
    return {"tenant": tenant, "quota": {"base": {k: v for k, v in con["d6-06"].items() if k != "byPrincipal"}, "byPrincipal": con["d6-06"].get("byPrincipal") or {}},
            "quotaEvents": quotas[:30], "spend": sorted(spend.values(), key=lambda x: -x["executed"]),
            "limits": {k: v for k, v in con["d6-07"].items() if k != "byPrincipal"}, "limitsByPrincipal": con["d6-07"].get("byPrincipal") or {},
            "approvals": cards[:20]}


# ── D7·D9 상시 점검 대상 (SCR-K02~K04·M02~M04) ─────────────────────
TWO_PERSON = {"allow", "pin-update", "release", "approve-sensitive"}
SENSITIVE_PERM = ("write", "net", "egress", "admin", "exec", "delete")


def _scan_records(s: Session, tenant: str | None, kinds: list[str], limit: int = 80) -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.kind == "scan")
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    out = []
    for r in s.scalars(q.order_by(models.Evidence.seq.desc()).limit(limit * 10)):
        if r.body.get("kind") in kinds:
            out.append(r)
            if len(out) >= limit:
                break
    return out


def supply_decisions(s: Session, tenant: str | None) -> dict[str, dict]:
    q = select(models.Evidence).where(models.Evidence.kind == "supply")
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    out: dict[str, dict] = {}
    for r in s.scalars(q.order_by(models.Evidence.seq)):
        out[r.ref_id] = r.body | {"at": r.created_at, "seq": r.seq}
    return out


def artifacts(s: Session, tenant: str | None, kinds: list[str]) -> dict:
    tq = select(models.ScanTarget).where(models.ScanTarget.kind.in_(kinds))
    qq = select(models.Quarantine).where(models.Quarantine.active.is_(True))
    if tenant:
        tq, qq = tq.where(models.ScanTarget.tenant == tenant), qq.where(models.Quarantine.tenant == tenant)
    recs = _scan_records(s, tenant, kinds)
    traces = [r.body.get("traceId") for r in recs if r.body.get("traceId")]
    ev: dict[str, list] = {}
    if traces:
        for f in s.scalars(select(models.Finding).where(models.Finding.trace_id.in_(traces))):
            if f.verdict != "allow":
                ev.setdefault(f.trace_id, []).append({"agent": f.agent_id, "ruleId": f.rule_id, "severity": f.severity, "finding": f.id,
                                                      "verdict": f.body.get("effectiveVerdict") or f.verdict,
                                                      "notes": [(e.get("location"), e.get("note")) for e in f.body.get("evidence", [])]})
    dec = supply_decisions(s, tenant)
    targets = [{"id": t.id, "kind": t.kind, "name": t.name, "artifact": t.artifact, "intervalSec": t.interval_sec,
                "lastRunAt": t.last_run_at.isoformat() if t.last_run_at else None, "lastVerdict": t.last_verdict,
                "decision": dec.get(f"{t.kind}:{t.name}")} for t in s.scalars(tq.order_by(models.ScanTarget.created_at))]
    scans = [{"seq": r.seq, "at": r.created_at, "kind": r.body.get("kind"), "name": r.body.get("name"), "target": r.body.get("target"),
              "verdict": r.body.get("verdict"), "traceId": r.body.get("traceId"), "by": r.body.get("by"), "hits": ev.get(r.body.get("traceId"), []),
              "quarantine": r.body.get("quarantine"), "decision": dec.get(f"{r.body.get('kind')}:{r.body.get('name')}")} for r in recs]
    return {"kinds": kinds, "targets": targets, "scans": scans,
            "quarantine": [{"id": q.id, "kind": q.kind, "value": q.value, "reason": q.reason, "at": q.created_at.isoformat()} for q in s.scalars(qq)
                           if q.kind in kinds or q.kind == "host"],
            "pending": [{"id": a.id, "summary": a.summary, "action": a.action, "createdAt": a.created_at.isoformat()}
                        for a in s.scalars(select(models.Approval).where(models.Approval.status == "pending") if not tenant else
                                           select(models.Approval).where(models.Approval.status == "pending", models.Approval.tenant == tenant))
                        if (a.action or {}).get("type") in ("supply_decision", "quarantine_release") and (a.action or {}).get("kind") in kinds + ["host"]]}


def decide_supply(s: Session, tenant: str, kind: str, name: str, decision: str, reason: str, by: str) -> dict:
    """심사·무결성·격리 결정 — 2인 결정(허용 예외·핀 갱신·격리 해제·쓰기/네트워크 권한 도구 승인)은 승인함으로, 나머지는 원장에 바로."""
    from app import approvals
    if not reason.strip():
        raise ValueError("사유 필수")
    if decision == "approve":
        t = s.scalars(select(models.ScanTarget).where(models.ScanTarget.tenant == tenant, models.ScanTarget.kind == kind,
                                                      models.ScanTarget.name == name)).first()
        perms = [str(p).lower() for p in ((t.artifact if t else {}) or {}).get("permissions", []) + ((t.artifact if t else {}) or {}).get("permissionsDeclared", [])]
        if any(k in p for p in perms for k in SENSITIVE_PERM):
            decision = "approve-sensitive"
    if decision in TWO_PERSON:
        typ = "quarantine_release" if decision == "release" else "supply_decision"
        a = approvals.create(s, secrets.token_hex(16), tenant, "offline", [], f"{kind} {name} — {decision}: {reason}", by,
                             action={"type": typ, "kind": kind, "name": name, "decision": decision, "reason": reason})
        return {"approvalRef": a.id, "status": a.status, "required": a.required, "decision": decision}
    rec = ledger.append(s, "supply", f"{kind}:{name}", {"event": "decided", "kind": kind, "name": name, "decision": decision, "reason": reason, "by": by}, tenant)
    out = {"seq": rec.seq, "decision": decision}
    if decision == "retest":
        t = s.scalars(select(models.ScanTarget).where(models.ScanTarget.tenant == tenant, models.ScanTarget.kind == kind, models.ScanTarget.name == name)).first()
        if t is not None:
            from app import scanner
            r = scanner.run_scan(s, t.artifact, tenant, target=t, by=by)
            out |= {"verdict": r["verdict"], "traceId": r["traceId"]}
    return out


def apply_supply(s: Session, approval: models.Approval) -> dict:
    act = approval.action or {}
    rec = ledger.append(s, "supply", f"{act['kind']}:{act['name']}", {"event": "decided", "kind": act["kind"], "name": act["name"],
                                                                      "decision": act["decision"], "reason": act.get("reason"),
                                                                      "by": f"approval:{approval.id}"}, approval.tenant)
    out = {"applied": act["type"], "decision": act["decision"], "name": act["name"], "seq": rec.seq}
    if act["type"] == "quarantine_release":
        for q in s.scalars(select(models.Quarantine).where(models.Quarantine.tenant == approval.tenant, models.Quarantine.value == act["name"],
                                                           models.Quarantine.active.is_(True))):
            q.active, q.released_by = False, f"approval:{approval.id}"
            out["released"] = q.id
    return out


# ── D8 메모리·컨텍스트 (SCR-L02·L03·L04) ─────────────────────────
def d8_memory(s: Session, tenant: str | None) -> dict:
    items: dict[str, dict] = {}
    for r in _all_gate(s, tenant, 24 * 7):
        for m in (r.body.get("shape") or {}).get("memory") or []:
            x = items.setdefault(m["id"], m | {"seen": 0, "last": r.created_at, "verdicts": {}})
            x["seen"] += 1
            v = r.body.get("verdict")
            x["verdicts"][v] = x["verdicts"].get(v, 0) + 1
    writes = []
    fs = findings(s, tenant, ["d8-02", "d8-04"], hours=24 * 7, limit=100)
    aprs = {a.trace_id: a for a in s.scalars(select(models.Approval).where(models.Approval.trace_id.in_([f.trace_id for f in fs])))} if fs else {}
    from app import approvals as _ap
    for f in fs:
        if f.verdict == "allow":
            continue
        a = aprs.get(f.trace_id)
        writes.append(finding_row(f) | {"approval": _ap.out(s, a) if a else None})
    return {"items": sorted(items.values(), key=lambda x: x["last"], reverse=True)[:80], "writes": writes[:30],
            "rescan": [finding_row(f) for f in findings(s, tenant, ["d8-03", "d8-06"], hours=24 * 7, limit=40) if f.verdict != "allow"],
            "note": "메모리 원문은 저장하지 않는다 — 항목 메타데이터(id·소유자·세션·작성자·승인·TTL)와 판정만"}


def d8_context(s: Session, tenant: str | None, trace: str | None) -> dict:
    out: dict = {"trace": trace}
    if trace:
        rec = gate_shapes(s, tenant, [trace]).get(trace)
        if rec is not None:
            sh = rec.get("shape") or {}
            q = select(models.Finding).where(models.Finding.trace_id == trace)
            if tenant:
                q = q.where(models.Finding.tenant == tenant)
            fs = [finding_row(f) for f in s.scalars(q)]
            def hits(prefix):
                return [{"agent": f["agent"], "ruleId": f["ruleId"], "verdict": f["effective"] or f["verdict"], "note": e.get("note")}
                        for f in fs if f["verdict"] != "allow" for e in f["evidence"] if (e.get("location") or "").startswith(prefix)]
            parts = []
            if sh.get("system") is not None:
                parts.append({"part": "system", "label": "시스템 지시", "trust": "T0", "chars": sh["system"], "hits": hits("system")})
            if sh.get("text") is not None:
                parts.append({"part": "text", "label": "사용자 입력", "trust": "T1", "chars": sh["text"], "hits": hits("text")})
            for g in sh.get("segments") or []:
                parts.append({"part": f"segments[{g['i']}]", "label": g["source"], "trust": "T1" if g["trust"] == "trusted" else "T3", "chars": g["chars"], "hits": hits(f"segments[{g['i']}]")})
            for d in sh.get("retrieval") or []:
                parts.append({"part": f"retrieval:{d['id']}", "label": d.get("source") or "index", "trust": "T2" if d.get("trust") == "trusted" else "T3",
                              "signed": d.get("signed"), "hits": hits(f"retrieval:{d['id']}") + hits(f"retrieval[")})
            for m in sh.get("memory") or []:
                parts.append({"part": f"memory:{m['id']}", "label": f"memory · {m.get('writer') or '—'}", "trust": "T2", "hits": hits(f"memory:{m['id']}")})
            out |= {"gate": rec.get("gate"), "verdict": rec.get("verdict"), "parts": parts, "findings": fs}
    out["stored"] = [finding_row(f) for f in findings(s, tenant, ["d8-04", "d8-03"], hours=24 * 7, limit=30) if f.verdict != "allow"]
    out["recentTraces"] = [r.ref_id for r in _all_gate(s, tenant, 24, 400) if (r.body.get("shape") or {}).get("retrieval") or (r.body.get("shape") or {}).get("segments")][:10]
    return out


def d8_bias(s: Session, tenant: str | None, days: int = 30) -> dict:
    import math
    cnt: dict[str, int] = {}
    per_day: dict[str, dict[str, int]] = {}
    for r in _all_gate(s, tenant, 24 * days):
        docs = (r.body.get("shape") or {}).get("retrieval") or []
        day = r.created_at[:10]
        for d in docs:
            src = d.get("source") or "index"
            cnt[src] = cnt.get(src, 0) + 1
            per_day.setdefault(day, {})
            per_day[day][src] = per_day[day].get(src, 0) + 1
    tot = sum(cnt.values())
    def ent(c):
        n = sum(c.values())
        if n == 0 or len(c) < 2:
            return 0.0
        return round(-sum(v / n * math.log(v / n) for v in c.values()) / math.log(len(c)), 3)
    p = policy.spec_of(policy.latest(s, "default", tenant or "default")).agent_params.get("d8-07", {})
    cap = p.get("maxSourceShare", 0.6)
    share = sorted(({"source": k, "count": v, "share": round(v / tot, 3)} for k, v in cnt.items()), key=lambda x: -x["count"])
    camp = s.scalars(select(models.Evidence).where(models.Evidence.kind == "redteam").order_by(models.Evidence.seq.desc()).limit(1)).first()
    a = s.get(models.Agent, "d8-07")
    sugg = [{"source": x["source"], "share": x["share"], "suggestedWeight": round(cap / x["share"], 2)} for x in share if x["share"] > cap]
    return {"days": days, "docs": tot, "sources": share[:10], "diversity": ent(cnt), "topShare": share[0]["share"] if share else None, "cap": cap,
            "trend": [{"day": k, "diversity": ent(v), "docs": sum(v.values())} for k, v in sorted(per_day.items())][-30:],
            "agentStatus": a.status if a else None, "fairness": (camp.body.get("fairness") or [])[:10] if camp else [],
            "findings": [finding_row(f) for f in findings(s, tenant, ["d8-07"], hours=24 * days, limit=20) if f.verdict != "allow"],
            "suggestions": sugg}
