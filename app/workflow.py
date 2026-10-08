"""작업 흐름 화면 (SCR-O06·B07·O07·R05) — 승인 결정 문맥·작업 트레이, 사고 대응 런북 실행·포렌식 보존·재현, 업데이트·자체 SBOM."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import approvals, domains, ledger, models, policy, registry
from app.models import utcnow


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── SCR-O06 승인 결정 문맥 · SCR-B07 트레이 ───────────────────────
def approval_context(s: Session, tenant: str | None, aid: str) -> dict | None:
    a = s.get(models.Approval, aid)
    if a is None or (tenant and a.tenant != tenant):
        return None
    gate = domains.gate_shapes(s, None, [a.trace_id]).get(a.trace_id) or {}
    sh = gate.get("shape") or {}
    fs = [domains.finding_row(f) for f in s.scalars(select(models.Finding).where(models.Finding.trace_id == a.trace_id))]
    act = sh.get("action") or {}
    pid = sh.get("principal")
    ap = policy.spec_of(policy.latest(s, "default", a.tenant)).agent_params
    def eff(agent):
        base = {k: v for k, v in (ap.get(agent) or {}).items() if k != "byPrincipal"}
        return base | (((ap.get(agent) or {}).get("byPrincipal") or {}).get(pid) or {})
    spend = None
    if act.get("amount") is not None:
        today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        spent = 0.0
        for r in domains._gate(s, a.tenant, "tool", 2000):
            sh2 = r.body.get("shape") or {}
            if sh2.get("principal") == pid and (sh2.get("action") or {}).get("amount") is not None and \
                    datetime.fromisoformat(r.created_at.replace("Z", "+00:00")) >= today and r.body.get("verdict") in ("allow", "alert"):
                spent += float(sh2["action"]["amount"])
        lim = eff("d6-07")
        daily = lim.get("dailyLimit")
        spend = {"amount": act["amount"], "spentToday": spent, "dailyLimit": daily, "approvalThreshold": lim.get("approvalThreshold", 100000),
                 "spendLimit": lim.get("spendLimit", 10_000_000), "after": spent + float(act["amount"]),
                 "ratio": round((spent + float(act["amount"])) / daily, 3) if daily else None,
                 "overLimit": bool(daily and spent + float(act["amount"]) > daily) or float(act["amount"]) > lim.get("spendLimit", 10_000_000),
                 "compensation": (lim.get("compensations") or {}).get(act.get("type"))}
    since = utcnow() - timedelta(hours=24)
    reps = s.scalar(select(func.count()).select_from(models.Approval).where(models.Approval.tenant == a.tenant,
                                                                              models.Approval.requested_by == a.requested_by,
                                                                              models.Approval.created_at >= since)) or 0
    x03 = [f for f in fs if f["agent"] == "x03" and f["verdict"] != "allow"]
    level = eff("d6-01").get("autonomyLevel", 1)
    grade = None
    if act:
        grade = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(act.get("impact", "low"), 0) + bool(act.get("external")) + (act.get("reversible") is False)
    return {"approval": approvals.out(s, a), "gate": {k: gate.get(k) for k in ("gate", "verdict", "policy", "stage", "profile")},
            "action": act or None, "tool": sh.get("tool"), "principal": pid, "onBehalfOf": sh.get("onBehalfOf"),
            "findings": fs, "spend": spend, "autonomy": {"level": level, "grade": grade},
            "trust": {"repeats24h": reps, "x03": x03, "urgency": any("긴급" in (e.get("note") or "") or "urgent" in (e.get("note") or "").lower()
                                                                       for f in x03 for e in f["evidence"]),
                      "warn": reps >= 3 or bool(x03)},
            "irreversible": act.get("reversible") is False if act else False}


def tray(s: Session, tenant: str | None, me: str) -> dict:
    q = select(models.Approval).where(models.Approval.status == "pending")
    if tenant:
        q = q.where(models.Approval.tenant == tenant)
    rows = sorted(s.scalars(q), key=lambda a: _utc(a.expires_at) if a.expires_at else _utc(a.created_at) + timedelta(days=365))
    traces = [a.trace_id for a in rows]
    shapes = domains.gate_shapes(s, None, traces)
    since = utcnow() - timedelta(hours=24)
    rep = dict(s.execute(select(models.Approval.requested_by, func.count()).where(models.Approval.created_at >= since)
                         .group_by(models.Approval.requested_by)).all())
    items = []
    for a in rows[:30]:
        sh = (shapes.get(a.trace_id) or {}).get("shape") or {}
        o = approvals.out(s, a)
        items.append({"id": a.id, "summary": a.summary, "gate": a.gate, "expiresAt": o["expiresAt"], "required": a.required,
                      "approvals": sum(d["decision"] == "approve" for d in o["decisions"]), "requestedBy": a.requested_by,
                      "principal": sh.get("principal"), "action": sh.get("action"), "tool": (sh.get("tool") or {}).get("name"),
                      "repeats24h": rep.get(a.requested_by, 0), "mine": a.requested_by == me,
                      "decidedByMe": any(d["principal"] == me for d in o["decisions"])})
    jobs = []
    for r in s.scalars(select(models.Evidence).where(models.Evidence.kind.in_(("redteam", "quality", "airgap", "review", "replay", "scan")))
                       .order_by(models.Evidence.seq.desc()).limit(80)):
        b = r.body
        name = {"redteam": "레드팀 캠페인", "airgap": "번들 반입", "review": "등록 심사", "replay": "포렌식 재현", "scan": "상시 점검"}.get(r.kind)
        if r.kind == "quality" and b.get("event") in ("golden_replay", "corpus_eval"):
            name = "골든셋 재생" if b["event"] == "golden_replay" else "코퍼스 평가"
        if name and (not tenant or r.tenant in (tenant, ledger.PLATFORM)):
            jobs.append({"kind": r.kind, "name": name, "at": r.created_at, "seq": r.seq, "status": "done",
                         "detail": b.get("verdict") or b.get("event") or ""})
        if len(jobs) >= 8:
            break
    return {"approvals": items, "jobs": jobs}


# ── SCR-O07 사고 대응 런북·포렌식 재현 ──────────────────────────────
PHASES = ("detect", "contain", "eradicate", "recover", "review")
STEPS: dict[str, list[dict]] = {
    "detect": [{"id": "triage", "ko": "사건 분류·영향 범위 확인(상관 판정·trace)", "en": "Triage — correlated verdicts · traces", "action": "note"}],
    "contain": [{"id": "quarantine-actor", "ko": "행위 주체 격리 — 관문 즉시 차단(격리 목록)", "en": "Quarantine the actor — gate blocks at once", "action": "quarantine"},
                {"id": "contain-flag", "ko": "봉쇄 완료 표시", "en": "Mark contained", "action": "contain"}],
    "eradicate": [{"id": "rotate-identity", "ko": "자격증명·워크로드 신원 회전(2인 승인)", "en": "Rotate credentials · workload identity (two approvals)", "action": "approval"},
                  {"id": "reassess", "ko": "영향 판정 재평가 — 현재 정책으로 다시 합성", "en": "Re-assess affected verdicts with the current policy", "action": "reassess"}],
    "recover": [{"id": "policy-hotfix", "ko": "정책 핫픽스 배포(시뮬레이터·단위 시험 통과 후)", "en": "Deploy policy hotfix (after simulator · unit tests)", "action": "policy"},
                {"id": "release", "ko": "격리 해제(재발 없음 확인)", "en": "Release quarantine (no recurrence)", "action": "release"}],
    "review": [{"id": "postmortem", "ko": "사후 검토 기록 — 원인·재발 방지", "en": "Post-incident review — cause · prevention", "action": "note"},
               {"id": "close", "ko": "사건 종결", "en": "Close incident", "action": "close"}],
}


def _incident(s: Session, tenant: str | None, iid: str) -> models.Incident:
    inc = s.get(models.Incident, iid)
    if inc is None or (tenant and inc.tenant != tenant):
        raise KeyError(iid)
    return inc


def response(s: Session, tenant: str | None, iid: str) -> dict:
    inc = _incident(s, tenant, iid)
    done: dict[str, dict] = {}
    forensic, replays = None, []
    for r in s.scalars(select(models.Evidence).where(models.Evidence.ref_id == iid, models.Evidence.kind.in_(("incident", "forensic", "replay")))
                       .order_by(models.Evidence.seq)):
        b = r.body
        if r.kind == "incident" and b.get("event") == "step_executed":
            done[b["step"]] = b | {"at": r.created_at, "seq": r.seq}
        elif r.kind == "forensic":
            forensic = b | {"at": r.created_at, "seq": r.seq, "hash": r.hash}
        elif r.kind == "replay":
            replays.append(b | {"at": r.created_at, "seq": r.seq})
    if inc.contained:
        done.setdefault("contain-flag", {"step": "contain-flag", "by": "—", "at": inc.updated_at.isoformat()})
    if inc.status == "closed":
        done.setdefault("close", {"step": "close", "by": inc.closed_by, "at": inc.updated_at.isoformat()})
    phase = next((p for p in PHASES if not all(st["id"] in done for st in STEPS[p])), "review")
    pend = [a for a in s.scalars(select(models.Approval).where(models.Approval.status == "pending")) if (a.action or {}).get("incident") == iid]
    return {"incident": {"id": inc.id, "title": inc.title, "domain": inc.domain, "severity": inc.severity, "status": inc.status,
                         "contained": inc.contained, "agents": inc.agent_ids, "rules": inc.rule_ids, "traces": inc.trace_ids[:20]},
            "phases": [{"id": p, "steps": [st | {"done": done.get(st["id"])} for st in STEPS[p]], "complete": all(st["id"] in done for st in STEPS[p])} for p in PHASES],
            "current": phase, "forensic": forensic, "replays": replays[-5:],
            "pending": [{"id": a.id, "summary": a.summary, "step": (a.action or {}).get("step")} for a in pend]}


def run_step(s: Session, tenant: str | None, iid: str, step: str, note: str, by: str) -> dict:
    from app import scanner
    inc = _incident(s, tenant, iid)
    st = next((x for p in PHASES for x in STEPS[p] if x["id"] == step), None)
    if st is None:
        raise ValueError(f"단계 {step} 없음")
    out: dict = {"step": step}
    if st["action"] == "quarantine":
        actors = sorted({(f.body.get("subject") or {}).get("principal", {}).get("id") for f in
                         s.scalars(select(models.Finding).where(models.Finding.id.in_(inc.finding_ids[:50]))) if (f.body.get("subject") or {}).get("principal")})
        out["quarantined"] = [scanner.quarantine(s, inc.tenant, "agent", a, f"사건 {iid} 봉쇄", inc.finding_ids[:20], by).id for a in actors if a]
    elif st["action"] == "contain":
        inc.contained, inc.updated_at = True, utcnow()
    elif st["action"] == "approval":
        a = approvals.create(s, secrets.token_hex(16), inc.tenant, "offline", inc.finding_ids[:20], f"사건 {iid} — {st['ko']}", by,
                             action={"type": "runbook_step", "incident": iid, "step": step})
        out["approvalRef"] = a.id
        s.flush()
        return out | {"pending": True}
    elif st["action"] == "reassess":
        out["reassessed"] = reassess(s, inc)
    elif st["action"] == "policy":
        cur = policy.latest(s, "default", inc.tenant)
        if cur is None or _utc(cur.created_at) <= _utc(inc.created_at):
            raise ValueError("사건 이후 배포된 정책 버전이 없다 — 시뮬레이터·단위 시험 후 배포 먼저 (/policies/edit)")
        out["policy"] = f"{cur.policy_id}@v{cur.version}"
    elif st["action"] == "release":
        for q in s.scalars(select(models.Quarantine).where(models.Quarantine.tenant == inc.tenant, models.Quarantine.active.is_(True))):
            if f"사건 {iid}" in (q.reason or ""):
                q.active, q.released_by = False, by
                out.setdefault("released", []).append(q.id)
    elif st["action"] == "close":
        if not inc.contained:
            raise ValueError("봉쇄(contain) 전에는 종결할 수 없다")
        inc.status, inc.closed_by, inc.updated_at = "closed", by, utcnow()
    rec = ledger.append(s, "incident", iid, {"event": "step_executed", "step": step, "note": note[:300], "by": by} | {k: v for k, v in out.items() if k != "step"},
                        inc.tenant)
    return out | {"seq": rec.seq}


def apply_runbook(s: Session, approval: models.Approval) -> dict:
    act = approval.action or {}
    from app import identity, secrets_broker
    r = identity.rotate(s, f"approval:{approval.id}", force=True)
    leases = secrets_broker.revoke_all(s, approval.tenant, f"approval:{approval.id}")
    ledger.append(s, "incident", act["incident"], {"event": "step_executed", "step": act["step"], "by": f"approval:{approval.id}",
                                                   "rotated": r.get("rotated"), "leasesRevoked": leases}, approval.tenant)
    return {"applied": "runbook_step", "step": act["step"], "incident": act["incident"], "leasesRevoked": leases}


def _finding(f: models.Finding):
    from aegis.schemas import Finding as F
    b = {k: v for k, v in f.body.items() if k != "effectiveVerdict"}
    b["action"] = {k: v for k, v in (b.get("action") or {}).items() if k != "transformApplied"}   # 저장본은 무해화 결과 대신 적용 여부만
    return F.model_validate(b | {"subject": b.get("subject") or {}})


def reassess(s: Session, inc: models.Incident) -> dict:
    """사건 판정을 현재 정책으로 다시 합성 — 원판정(에이전트 출력)은 그대로, 유효 판정 변화만 본다(원문 불필요)."""
    spec = policy.spec_of(policy.latest(s, "default", inc.tenant))
    rows = []
    for f in s.scalars(select(models.Finding).where(models.Finding.id.in_(inc.finding_ids[:50]))):
        try:
            fd = _finding(f)
        except Exception:  # noqa: BLE001 — 저장 본문 형식 차이는 건너뛴다
            continue
        v, why = policy.effective(fd, spec, "enforce")
        rows.append({"finding": f.id, "agent": f.agent_id, "before": f.body.get("effectiveVerdict") or f.verdict, "after": v, "reasons": why})
    return {"total": len(rows), "changed": [r for r in rows if r["before"] != r["after"]]}


def preserve(s: Session, tenant: str | None, iid: str, by: str) -> dict:
    """포렌식 보존 — 판정·판정 기록(seq·해시)·정책 버전·에이전트 버전·상시 점검 대상(artifact)을 사건에 묶고 법적 보존(만료 제외) 표시.
    입력 원문은 보존하지 않는다(원문 미보존 설정 유지 — 근거 구간만)."""
    inc = _incident(s, tenant, iid)
    fs = list(s.scalars(select(models.Finding).where(models.Finding.id.in_(inc.finding_ids[:200]))))
    gates = list(s.scalars(select(models.Evidence).where(models.Evidence.kind.in_(("gate", "scan")), models.Evidence.ref_id.in_(inc.trace_ids[:200]))))
    pol = policy.latest(s, "default", inc.tenant)
    bundle = {"findings": [{"id": f.id, "agent": f.agent_id, "version": (f.body.get("agent") or {}).get("version"), "ruleId": f.rule_id,
                            "verdict": f.verdict, "effective": f.body.get("effectiveVerdict"), "confidence": f.confidence} for f in fs],
              "records": [{"seq": r.seq, "kind": r.kind, "hash": r.hash} for r in gates],
              "policy": {"ref": f"{pol.policy_id}@v{pol.version}", "body": pol.body} if pol else None,
              "agents": {a.id: a.version for a in s.scalars(select(models.Agent).where(models.Agent.id.in_(inc.agent_ids)))}}
    digest = hashlib.sha256(json.dumps(bundle, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
    rec = ledger.append(s, "forensic", iid, {"event": "preserved", "legalHold": True, "digest": digest, "counts": {k: len(v) for k, v in bundle.items() if isinstance(v, (list, dict)) and k != "policy"},
                                            "bundle": bundle, "by": by, "raw": "원문 미보존 — 근거 구간만"}, inc.tenant)
    return {"seq": rec.seq, "digest": digest, "findings": len(fs), "records": len(gates)}


def replay(s: Session, tenant: str | None, iid: str, by: str) -> dict:
    """재현 — 보존본 기준으로 (1) 상시 점검 판정은 대상 artifact 를 현재 에이전트로 다시 판정, (2) 인라인 판정은 원문이 없으므로
    보존된 원판정을 보존 정책으로 다시 합성해 유효 판정 일치를 확인하고, 에이전트 버전 차이를 원인 후보로 표시. L3 격리 런타임이
    없으면 프로세스 안(L0) 재생."""
    from aegis.schemas import JudgeRequest
    from app import sandbox
    inc = _incident(s, tenant, iid)
    fr = s.scalars(select(models.Evidence).where(models.Evidence.kind == "forensic", models.Evidence.ref_id == iid).order_by(models.Evidence.seq.desc())).first()
    if fr is None:
        raise ValueError("포렌식 보존 먼저 (:preserve)")
    b = fr.body["bundle"]
    spec = policy.PolicySpec.model_validate((b.get("policy") or {}).get("body", {}).get("spec", {})) if b.get("policy") else policy.PolicySpec()
    rows = []
    stored = {f.id: f for f in s.scalars(select(models.Finding).where(models.Finding.id.in_([x["id"] for x in b["findings"]])))}
    for x in b["findings"]:
        f = stored.get(x["id"])
        if f is None:
            continue
        cur_v = registry.runtime_agent(f.agent_id).manifest.metadata.version if s.get(models.Agent, f.agent_id) else None
        mode, got = "policy", None
        if f.gate == "offline":
            tgt = None
            for r in s.scalars(select(models.Evidence).where(models.Evidence.kind == "scan", models.Evidence.ref_id.in_(inc.trace_ids))):
                tgt = r.body.get("target")
            t = s.get(models.ScanTarget, tgt) if tgt else None
            if t is not None:
                got = registry.runtime_agent(f.agent_id).judge(JudgeRequest(gate="offline", artifact=t.artifact)).verdict
                mode = "artifact"
        if got is None:
            got = policy.effective(_finding(f), spec, "enforce")[0]
            want = x.get("effective") or x["verdict"]
        else:
            want = x["verdict"]
        rows.append({"finding": f.id, "agent": f.agent_id, "mode": mode, "expected": want, "replayed": got, "match": want == got,
                     "versionThen": x.get("version"), "versionNow": cur_v, "versionChanged": bool(x.get("version") and cur_v and x["version"] != cur_v)})
    isolation = "L3" if sandbox.available("L3") else "L0 (L3 런타임 없음 — 프로세스 안 재생)"
    rec = ledger.append(s, "replay", iid, {"event": "replayed", "isolation": isolation, "total": len(rows), "matched": sum(r["match"] for r in rows),
                                          "rows": rows[:100], "forensicSeq": fr.seq, "by": by}, inc.tenant)
    return {"seq": rec.seq, "isolation": isolation, "total": len(rows), "matched": sum(r["match"] for r in rows), "rows": rows}


# ── SCR-R05 업데이트·자체 SBOM ────────────────────────────────────
def updates(s: Session) -> dict:
    from importlib.metadata import version as pv
    agents = [{"id": a.id, "name": a.name, "nameKo": a.name_ko, "version": a.version, "origin": a.origin, "status": a.status,
               "updatedAt": a.updated_at.isoformat() if a.updated_at else None} for a in s.scalars(select(models.Agent).order_by(models.Agent.id))]
    hist = [{"seq": r.seq, "at": r.created_at, "event": r.body.get("event"), "version": r.body.get("version"), "detail": r.body.get("detail") or r.body.get("step"),
             "applied": r.body.get("applied"), "agent": r.body.get("agent")}
            for r in s.scalars(select(models.Evidence).where(models.Evidence.kind.in_(("airgap", "update"))).order_by(models.Evidence.seq.desc()).limit(30))]
    try:
        plat = pv("aegismesh")
    except Exception:  # noqa: BLE001 — 개발 설치는 패키지 메타데이터가 없을 수 있다
        plat = "0.1.0"
    from app import pins
    return {"platform": plat, "agents": agents, "history": hist, "pins": pins.check(),
            "rolling": "에이전트별 교체 — 품질 게이트(골든·공격 재생) 통과 시에만 새 인스턴스로, 실패하면 기존 인스턴스 유지(자동 롤백). 관문 재기동 없음"}


def reload_agent(s: Session, aid: str, by: str) -> dict:
    """롤링 교체 1건 — 디스크(또는 반입 번들)의 에이전트를 새로 적재해 품질 게이트를 돌리고, 통과하면 런타임 캐시를 교체한다."""
    from aegis.agent import load_agent
    from aegis.harness import evaluate
    row = s.get(models.Agent, aid)
    if row is None:
        raise KeyError(aid)
    before = row.version
    try:
        fresh = load_agent(aid) if row.origin == "builtin" else None
        rep = evaluate(fresh, repeat=1) if fresh else None
        ok = rep is not None and not rep.failures()
        after = fresh.manifest.metadata.version if fresh else before
    except Exception as exc:  # noqa: BLE001 — 적재 실패 = 롤백
        ok, after, rep = False, before, None
        err = str(exc)[:200]
    else:
        err = None if ok else "; ".join(rep.failures())[:300] if rep else "외부 에이전트는 반입 번들로 교체"
    if ok:
        registry.runtime_agent.cache_clear()
        m = fresh.manifest                                              # 버전만이 아니라 저장된 매니페스트도 새 판으로(기본 엔진·규칙 표시가 낡지 않게)
        row.version, row.manifest = after, m.model_dump(by_alias=True, mode="json")
        row.name, row.name_ko, row.latency_budget_ms, row.fail_mode = m.metadata.name, m.metadata.name_ko, m.spec.latency_budget_ms, m.spec.fail_mode
    rec = ledger.append(s, "update", aid, {"event": "agent_reloaded" if ok else "agent_rollback", "agent": aid, "from": before, "to": after,
                                          "detail": err, "by": by})
    return {"agent": aid, "ok": ok, "from": before, "to": after, "detail": err, "seq": rec.seq}


def release_sbom(s: Session) -> dict:
    """자체 릴리스 SBOM(SCR-R05 #8 — 의존성·활성 에이전트, airgap.release_sbom) + 분리형 서명(EdDSA, 플랫폼 신원 키)."""
    from app import airgap, identity
    r = airgap.release_sbom(s)
    body = json.dumps(r["sbom"], sort_keys=True, separators=(",", ":")).encode()
    sig = identity.signing_key().sign(body)
    return r | {"signature": {"alg": "EdDSA", "kid": identity.kid(), "sig": identity._b64(sig), "sha256": hashlib.sha256(body).hexdigest(),
                              "verify": "JWKS: /v1/identity/jwks — 정렬 JSON(separators , :) 바이트에 대한 Ed25519 서명"}}
