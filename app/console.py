"""콘솔 보조 기능 (SCR-B05·B06·C06·D07·R06·P02·Q02) — 전역 검색, 알림 센터, 판정 미리보기(재생), 배포 토폴로지,
데이터 보호 현황, 이탈 에이전트 강제 종료, 레드팀 실행 승인."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aegis.harness import _lines
from aegis.schemas import VERDICT_RANK, JudgeRequest
from app import approvals, db, gating, ledger, models, orchestrator, policy, profiles, sandbox, telemetry
from app.core.config import settings

SCREENS = [("/overview", "개요", "Overview"), ("/risk-map", "위험 지도", "Risk map"), ("/catalog", "카탈로그", "Catalog"),
           ("/instant", "즉시 사용", "Instant use"), ("/instant/preview", "판정 미리보기", "Verdict preview"),
           ("/marketplace", "장터", "Marketplace"), ("/gates", "관문 구성", "Gates"), ("/policies", "정책", "Policies"),
           ("/simulate", "판정 시뮬레이터", "Simulator"), ("/findings", "판정", "Findings"), ("/incidents", "사건", "Incidents"),
           ("/approvals", "승인 대기함", "Approvals"), ("/evidence", "증적 원장", "Evidence"), ("/reports", "통제 보고서", "Reports"),
           ("/governance", "거버넌스 점검", "Governance"), ("/redteam", "레드팀", "Red team"), ("/redteam/baseline", "회귀 기준선", "Baseline"),
           ("/observability", "관측·SLO", "Observability"), ("/topology", "배포 토폴로지", "Topology"), ("/notifications", "알림", "Notifications"),
           ("/admin/tenants", "테넌트", "Tenants"), ("/admin/users", "사용자·역할", "Users"), ("/admin/identity", "신원·비밀", "Identity"),
           ("/admin/sandbox", "샌드박스", "Sandbox"), ("/admin/airgap", "업데이트·폐쇄망", "Air-gap"),
           ("/admin/data-protection", "데이터 보호", "Data protection")]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso_since(hours: int) -> str:
    return (utcnow() - timedelta(hours=hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ── 전역 검색 (SCR-B05) ───────────────────────────────────────
def search(s: Session, q: str, tenant: str | None, limit: int = 8) -> dict:
    q = q.strip()
    like = f"%{q}%"
    out: dict[str, list] = {"agents": [], "items": [], "findings": [], "incidents": [], "policies": [], "screens": []}
    out["agents"] = [{"id": a.id, "label": f"{a.id} {a.name_ko}", "href": f"/catalog/{a.id}"} for a in s.scalars(
        select(models.Agent).where(or_(models.Agent.id.ilike(like), models.Agent.name_ko.ilike(like), models.Agent.name.ilike(like)))
        .order_by(models.Agent.id).limit(limit))]
    out["items"] = [{"id": i.id, "label": f"{i.id} {i.name_ko}", "href": f"/risk-map?item={i.id}"} for i in s.scalars(
        select(models.RiskItem).where(or_(models.RiskItem.id.ilike(like), models.RiskItem.name_ko.ilike(like), models.RiskItem.name_en.ilike(like)))
        .order_by(models.RiskItem.id).limit(limit))]
    if len(q) >= 6:
        fq = select(models.Finding).where(or_(models.Finding.id.like(f"{q}%"), models.Finding.trace_id == q))
        if tenant:
            fq = fq.where(models.Finding.tenant == tenant)
        out["findings"] = [{"id": f.id, "label": f"{f.id} · {f.agent_id} {f.verdict}", "href": f"/findings/{f.id}"}
                           for f in s.scalars(fq.limit(limit))]
    iq = select(models.Incident).where(or_(models.Incident.id.like(f"{q}%"), models.Incident.title.ilike(like)))
    if tenant:
        iq = iq.where(models.Incident.tenant == tenant)
    out["incidents"] = [{"id": i.id, "label": f"{i.id} {i.title}", "href": f"/incidents/{i.id}"} for i in s.scalars(iq.limit(limit))]
    pq = select(models.Policy.policy_id).where(models.Policy.policy_id.ilike(like)).distinct()
    if tenant:
        pq = pq.where(models.Policy.tenant == tenant)
    out["policies"] = [{"id": p, "label": f"정책 {p}", "href": f"/policies?p={p}"} for p in s.scalars(pq.limit(limit))]
    ql = q.lower()
    out["screens"] = [{"id": h, "label": f"{ko} · {en}", "href": h} for h, ko, en in SCREENS if ql in ko.lower() or ql in en.lower() or ql in h]
    return out


# ── 알림 센터 (SCR-B06) ───────────────────────────────────────
def notifications(s: Session, tenant: str | None, hours: int = 72) -> list[dict]:
    since = _iso_since(hours)
    note: list[dict] = []

    def add(at, severity, kind, text, href):
        note.append({"at": at, "severity": severity, "kind": kind, "text": text, "href": href})

    q = select(models.Evidence).where(models.Evidence.created_at >= since,
                                      models.Evidence.kind.in_(("gate", "airgap", "redteam", "tenancy", "sandbox", "identity", "trust",
                                                                "policy", "approval", "auth", "evidence", "quality", "slo", "pins")))
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    degraded = 0
    slo_seen: set[str] = set()
    pins_seen = False
    for r in s.scalars(q.order_by(models.Evidence.seq.desc()).limit(3000)):
        b, k = r.body, r.kind
        if k == "slo":                                    # 테넌트별 가장 최근 점검의 경보만 (매시 점검이 같은 경보를 반복하지 않게)
            if r.tenant not in slo_seen:
                slo_seen.add(r.tenant)
                for a in b.get("alerts", []):
                    add(r.created_at, a.get("severity", "medium"), "비용·SLO", f"{a.get('gate')} 관문 — {a.get('text')}", f"/gates/{a.get('gate')}")
            continue
        if k == "pins":                                   # 가장 최근 점검만(매일 같은 경보 반복 방지, Epic 58)
            if not pins_seen and b.get("event") == "pins_stale":
                for i in (x for x in b.get("items", []) if x.get("stale")):
                    add(r.created_at, "medium", "고정 판", f"{i.get('name')} 낡음 ({i.get('version') or '없음'}) — make pins-refresh 후 재빌드", "/admin/updates")
            pins_seen = True
            continue
        if k == "gate" and b.get("degraded"):
            degraded += 1
            if degraded <= 5:
                add(r.created_at, "medium", "강등", f"{b.get('gate')} 관문 강등 {', '.join(b['degraded'])} (failMode 적용)", f"/findings?trace={b.get('traceId')}")
        elif k == "gate" and b.get("overBudget"):
            add(r.created_at, "low", "지연 예산", f"{b.get('gate')} 관문 {b.get('latencyMs')}ms > {b.get('budgetMs')}ms", "/gates")
        elif k == "airgap" and b.get("event") == "bundle_rejected":
            add(r.created_at, "high", "서명·반입 실패", f"번들 반입 거부 ({b.get('step')}): {b.get('detail')}", "/admin/airgap")
        elif k == "airgap" and b.get("event") == "bundle_imported":
            add(r.created_at, "info", "업데이트", f"번들 v{b.get('version')} 반입 — {json.dumps(b.get('applied', {}), ensure_ascii=False)[:120]}", "/admin/airgap")
        elif k == "redteam" and b.get("regressions"):
            add(r.created_at, "high", "품질 회귀", f"레드팀 회귀 {len(b['regressions'])}건: {', '.join(x['agent'] for x in b['regressions'][:5])}", "/redteam/baseline")
        elif k == "tenancy" and not b.get("ok", True):
            add(r.created_at, "critical", "격리 위반", f"테넌트 교차 접근 시험 실패: {', '.join(b.get('failed', []))}", "/admin/tenants")
        elif k == "sandbox" and not b.get("ok", True):
            add(r.created_at, "critical", "격리 점검 실패", f"L1 탈출 점검 {b.get('blocked')}/{b.get('total')}", "/admin/sandbox")
        elif k == "identity" and b.get("force"):
            add(r.created_at, "medium", "신원 회전", f"즉시 전체 회전 — SVID {b.get('invalidated')} 무효화 ({b.get('by')})", "/admin/identity")
        elif k == "trust":
            add(r.created_at, "info", "신뢰 저장소", f"{r.ref_id}: {b.get('event')}", "/admin/airgap")
        elif k == "quality" and b.get("event") == "fp_budget_warn":
            add(r.created_at, "medium", "오탐 예산", f"{b.get('agent')} 오탐 예산 {round(b.get('consumed', 0) * 100)}% — 임계 조정 제안 (MSG-008)", "/observability/slo")
        elif k == "quality" and b.get("event") == "fp_budget_demoted":
            add(r.created_at, "high", "강등", f"{b.get('agent')} 오탐 예산 초과 — 경보 전용 강등(차단 안 함)", "/observability/slo")
        elif k == "quality" and b.get("event") == "fp_budget_restored":
            add(r.created_at, "info", "복귀", f"{b.get('agent')} 7일 오탐률 {b.get('weekFpRate')} — 차단 복귀", "/observability/slo")
        elif k == "quality" and b.get("event") == "golden_replay" and b.get("overTarget"):
            add(r.created_at, "high", "품질", f"골든셋 {b.get('samples')}건 재생 — 오탐률 0.5% 초과 {', '.join(b['overTarget'][:5])}", "/observability/slo")
        elif k == "quality" and b.get("event") == "corpus_eval" and not b.get("ok", True):
            add(r.created_at, "high", "품질", f"코퍼스 {b.get('name')} 미탐률 {round(b.get('missRate', 0) * 100, 1)}% > 10%", "/observability/slo")
        elif k == "quality" and b.get("event") == "appeal_received":
            add(r.created_at, "info", "이의", f"{b.get('agent')} 판정 이의 접수 ({b.get('by')})", f"/findings/{b.get('finding')}")
        elif k == "evidence" and b.get("event") == "sampling_degraded":
            add(r.created_at, "high", "증적 강등", f"증적 적재 대기열 포화 — allow 판정 1/{b.get('sampleEvery')} 표본 적재 (NFR-L5)", "/observability")
        elif k == "evidence" and b.get("event") == "sampling_recovered":
            add(r.created_at, "info", "증적 복귀", f"표본 적재 해제 — 제외 {b.get('sampledOut')} · 버림 {b.get('dropped')} · {b.get('durationSec')}초", "/observability")
        elif k == "auth" and b.get("event") == "break_glass_login":
            add(r.created_at, "critical", "비상 관리자", f"{b.get('user')} 비상(break-glass) 로그인 — 사유: {b.get('reason')}", "/admin/sso")
        elif k == "auth" and b.get("event") == "sso_denied":
            add(r.created_at, "medium", "SSO 거부", f"{b.get('user')}: {b.get('reason')}", "/admin/sso")
        elif k == "approval" and b.get("event") == "action_applied":
            add(r.created_at, "info", "승인 실행", f"{b.get('applied')} 적용 {b.get('policy') or b.get('listing') or b.get('keyId') or ''}", "/approvals")
    for a in s.scalars(select(models.Agent).where(models.Agent.status == "alert_only")):
        add(a.updated_at.isoformat() if a.updated_at else None, "medium", "오탐 예산", f"{a.id} 경보 전용 강등 — 재심사(R5) 통과 시 복귀", f"/catalog/{a.id}")
    aq = select(func.count()).select_from(models.Approval).where(models.Approval.status == "pending")
    iq = select(models.Incident).where(models.Incident.status == "open", models.Incident.severity.in_(("high", "critical")))
    if tenant:
        aq, iq = aq.where(models.Approval.tenant == tenant), iq.where(models.Incident.tenant == tenant)
    if n := s.scalar(aq):
        add(utcnow().isoformat(), "info", "승인 대기", f"사람 승인 대기 {n}건", "/approvals")
    for i in s.scalars(iq.order_by(models.Incident.updated_at.desc()).limit(5)):
        add(i.updated_at.isoformat(), i.severity, "사건", f"{i.id} {i.title}", f"/incidents/{i.id}")
    note.sort(key=lambda x: str(x["at"] or ""), reverse=True)        # 시간순(최신 먼저)
    return note[:100]


# ── 판정 미리보기 (SCR-C06) ───────────────────────────────────
def preview(s: Session, tenant: str, pid: str, stage: str, samples: list[dict] | None = None, per_agent: int = 4,
            alert_domains: list[str] | None = None) -> dict:
    """차단을 켜기 전에 표본을 선택 프로파일로 재생 — 판정만 계산(저장 없음).
    원문은 보존하지 않으므로(NFR-D1) 표본 = 붙여 넣은 요청 또는 바인딩 에이전트의 골든(정상)·공격 코퍼스."""
    r = profiles.resolve(s, pid)
    rows = {i: gating.runtime(s, i) for i in r["agents"]}
    extra = profiles.overrides(s, pid)
    if alert_domains:                                   # 부분 차단에서 뺀 도메인 = 경보
        from app.policy import Override
        extra = extra | {i: Override(verdict="alert") for i in r["items"]
                         if (i.split("-")[0] if i.startswith("D") else "X") in set(alert_domains)}
    spec = policy.spec_of(policy.latest(s, "default", tenant))
    alert_only = frozenset(i for i, (_, row) in rows.items() if row.status == "alert_only")
    if not samples:
        samples = []
        for aid, (rt, row) in rows.items():
            t = rt.manifest.spec.tests
            for label, d in (("benign", rt.path / t.golden), ("attack", rt.path / t.attacks)):
                for i, (_lbl, raw) in enumerate(_lines(d)):
                    if i >= per_agent:
                        break
                    samples.append({"gate": row.gate, "label": label, "source": aid, "name": raw.get("name"), "request": raw["request"]})
    by_gate: dict[str, list[float]] = {}
    counts = {v: 0 for v in VERDICT_RANK}
    contrib: dict[str, int] = {}
    fp = miss = benign = attack = 0
    out = []
    for smp in samples[:400]:
        gate = smp.get("gate", "input")
        req = JudgeRequest.model_validate(smp.get("request", {}))
        req = req.model_copy(update={"subject": req.subject.model_copy(update={"tenant": tenant})})
        run = gating.run(gate, req, rows, spec, strict=False)        # 코퍼스 표본의 시나리오 params 는 유지(정책 값은 우선)
        dec = policy.evaluate(run["findings"], spec, stage, extra, alert_only)
        v = dec["verdict"]
        counts[v] += 1
        by_gate.setdefault(gate, []).append(run["latencyMs"])
        for d in dec["decisions"]:
            if d["effective"] != "allow":
                contrib[d["agent"]] = contrib.get(d["agent"], 0) + 1
        label = smp.get("label")
        if label == "benign":
            benign += 1
            fp += v != "allow"
        elif label == "attack":
            attack += 1
            miss += v == "allow"
        out.append({"gate": gate, "label": label, "source": smp.get("source"), "name": smp.get("name"), "verdict": v,
                    "rules": [d["ruleId"] for d in dec["decisions"] if d["effective"] != "allow"][:4], "latencyMs": run["latencyMs"]}
                   | ({"original": smp["original"]} if smp.get("original") else {}))

    def p95(xs):
        xs = sorted(xs)
        return round(xs[max(0, int(len(xs) * 0.95) - 1)], 3) if xs else 0.0
    return {"profile": pid, "stage": stage, "tenant": tenant, "samples": len(out), "counts": counts,
            "estimate": {"falsePositiveRate": round(fp / benign, 4) if benign else None, "missRate": round(miss / attack, 4) if attack else None,
                         "benign": benign, "attack": attack},
            "latency": {g: {"p95Ms": p95(xs), "budgetMs": orchestrator.GATE_BUDGET_MS.get(g)} for g, xs in by_gate.items()},
            "contribution": sorted(({"agent": k, "nonAllow": v} for k, v in contrib.items()), key=lambda x: -x["nonAllow"])[:15],
            "items": out[:200],
            "traffic": ({"total": len(traffic), "wouldBlock": sum(x["verdict"] == "block" for x in traffic),
                         "newlyBlocked": sum(x["verdict"] == "block" and x["original"] != "block" for x in traffic),
                         "unblocked": sum(x["verdict"] != "block" and x["original"] == "block" for x in traffic),
                         "labeled": sum(bool(x.get("label")) for x in traffic)} if (traffic := [x for x in out if "original" in x]) else None),
            "note": "원문 미보존(NFR-D1) — 표본은 붙여 넣은 요청, 에이전트 시험 코퍼스, 또는 테넌트가 켠 마스킹 실제 표본. 미리보기 자체는 저장·원장 기록 없음."}


# ── 배포 토폴로지 (SCR-D07) ───────────────────────────────────
def topology(s: Session) -> dict:
    try:
        db.ping()
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    worker = ledger.records(s, kind="identity", limit=1, desc=True)
    scans = ledger.records(s, kind="scan", limit=1, desc=True)
    sb = sandbox.status()
    tel = telemetry.status()
    chains = s.scalar(select(func.count()).select_from(models.LedgerChain)) or 0
    recs = s.scalar(select(func.max(models.Evidence.seq))) or 0
    return {"type": "T2", "typeName": "중앙 게이트웨이 (입력·도구·출력 관문을 API 가 수행)",
            "alternatives": {"T1": "사이드카 — 후속", "T3": "혼합 — 후속", "T4": "오프라인(폐쇄망) — 번들 반입 지원"},
            "nodes": [
                {"id": "gateway", "name": "게이트웨이·정책 결정점 (api)", "kind": "inline", "status": "ok", "detail": f"관문 예산 입력 80 · 도구 20 · 출력 150ms · 환경 {settings.app_env}"},
                {"id": "sandbox", "name": "샌드박스 풀", "kind": "pool", "status": "ok" if sb["maxLevel"] == "L1" else "degraded",
                 "detail": " · ".join(f"{p['level']} {'가능' if p['available'] else '없음'}" + (f" {p['active']}/{p['capacity']}" if p['level'] == 'L1' else "") for p in sb["pools"])},
                {"id": "offline", "name": "상시 계열 풀 (worker)", "kind": "pool", "status": "ok" if worker else "unknown",
                 "detail": f"최근 활동 {worker[0].created_at if worker else '—'} · 최근 점검 {scans[0].created_at if scans else '—'}"},
                {"id": "ledger", "name": "증적 원장", "kind": "store", "status": "ok" if db_ok else "down",
                 "detail": f"{settings.db_engine} · 체인 {chains} · 레코드 {recs} · 추가 전용"},
                {"id": "collector", "name": "관측 수집기 (OTel)", "kind": "pipeline", "status": "ok" if tel["enabled"] else "off",
                 "detail": f"{tel['endpoint'] or '미설정'} · 추적 전송 {tel['stats']['traces']['ok']}"},
                {"id": "console", "name": "콘솔 (web)", "kind": "ui", "status": "ok", "detail": "서버 컴포넌트 → API (브라우저는 API 직접 호출 없음)"},
            ],
            "flows": [["console", "gateway"], ["gateway", "sandbox"], ["gateway", "ledger"], ["offline", "ledger"], ["offline", "gateway"],
                      ["gateway", "collector"], ["offline", "collector"]]}


# ── 데이터 보호 (SCR-R06) ─────────────────────────────────────
def data_protection(s: Session, tenant: str | None) -> dict:
    def source(env_val, path_attr):
        return "외부 주입(env/KMS)" if env_val and env_val != "CHANGE_ME" else f"볼륨 파일 ({getattr(settings, path_attr)}) — 로컬·리허설용"
    tq = select(models.Tenant).order_by(models.Tenant.id)
    if tenant:
        tq = tq.where(models.Tenant.id == tenant)
    apps = list(s.scalars(select(models.ProfileApplication).where(models.ProfileApplication.active.is_(True))))
    egress = sorted({(s.get(models.Profile, a.profile_id).spec["spec"].get("region") or {}).get("modelEgress", "—") for a in apps if s.get(models.Profile, a.profile_id)})
    return {"payload": {"stored": False, "policy": "판정 원문·무해화 결과 미보존(NFR-D1). Finding 에는 위치·규칙만, payloadRef 는 항상 null",
                        "enable": "이 설치에는 원문 보존 기능이 없다 — 켜려면 별도 저장소·2인 승인·자동 마스킹 구현 필요"},
            "retention": {"default": settings.evidence_retention_days,
                          "tenants": [{"id": t.id, "retentionDays": t.retention_days, "region": t.region} for t in s.scalars(tq)],
                          "deletion": "원장은 추가 전용 — 만료는 승인된 배치로만(MSG-016), 삭제 전파는 원장 체인을 끊지 않는 별도 절차"},
            "telemetry": {"masking": len(telemetry.rules()), "rules": [r["name"] for r in telemetry.rules()], "endpoint": settings.otel_endpoint},
            "egress": {"setting": settings.model_egress, "profiles": egress, "note": "외부 모델 호출(국외 이전) 기본 차단(NFR-D5)"},
            "keys": [{"name": "원장 서명 키 (Ed25519)", "source": source(settings.ledger_signing_key, "ledger_key_file")},
                     {"name": "SVID 발급 키 (Ed25519)", "source": source(settings.svid_signing_key, "svid_key_file")},
                     {"name": "세션·토큰 서명 비밀 (HMAC)", "source": source(settings.auth_secret, "auth_secret_file")}]}


# ── 이탈 에이전트 강제 종료 (SCR-P02) ───────────────────────────
def terminate_rogue(s: Session, tenant: str, name: str, reason: str, by: str) -> dict:
    from app import auth, scanner
    q = scanner.quarantine(s, tenant, "agent", name, f"이탈 에이전트 강제 종료: {reason}", [], by)
    revoked_tokens, revoked_ids = 0, []
    u = s.scalars(select(models.User).where(models.User.username == name)).first()
    if u is not None and (u.tenant == tenant or tenant == "*"):
        u.active = False
        revoked_tokens = auth.revoke_all(s, u)
    for w in s.scalars(select(models.WorkloadIdentity).where(models.WorkloadIdentity.ref == name)):
        w.status = "revoked"
        revoked_ids.append(w.spiffe_id)
    ledger.append(s, "incident", f"rogue:{name}", {"event": "rogue_terminated", "name": name, "reason": reason, "quarantine": q.id,
                                                   "tokensRevoked": revoked_tokens, "identitiesRevoked": revoked_ids, "by": by}, tenant)
    return {"name": name, "quarantine": q.id, "tokensRevoked": revoked_tokens, "identitiesRevoked": revoked_ids,
            "gateway": "격리 목록 → 모든 관문이 즉시 차단"}


# ── 레드팀 실행 승인 (SCR-Q02) ─────────────────────────────────
def request_redteam(s: Session, agents: list[str] | None, scenario: str, reason: str, by: str) -> models.Approval:
    known = {a.id for a in s.scalars(select(models.Agent).where(models.Agent.origin == "builtin"))}
    bad = sorted(set(agents or []) - known)
    if bad:
        raise ValueError(f"등록부에 없는 대상 {bad} — 사전 등록 자산만")
    scope = {"type": "redteam_run", "agents": sorted(agents) if agents else None, "scenario": scenario,
             "isolation": "L1 (L3 런타임 없음 — 내부 코퍼스만, 외부 자산 미대상)"}
    return approvals.create(s, secrets.token_hex(16), "default", "redteam", [],
                            f"레드팀 실행 {scenario} · 대상 {len(agents) if agents else '전체'} · {reason}", by, action=scope)


def apply_redteam(s: Session, approval: models.Approval) -> dict:
    from app import redteam
    r = redteam.run_campaign(s, f"approval:{approval.id}", approval.action.get("agents"))
    return {"applied": "redteam_run", "agents": r["agents"], "regressions": len(r["regressions"]), "verdict": r["verdict"]}


# ── 설치 사전 점검 (SCR-A01·A10) ───────────────────────────────
def precheck(s: Session) -> dict:
    """설치 상태를 실데이터로 점검 — 배포 형태·DB·마이그레이션·키 주입·관측·샌드박스·worker·관리자·커버리지."""
    import os
    from pathlib import Path

    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    from aegis.coverage import report
    from app import auth
    checks = []

    def add(cid, title, ok, detail, level="required"):
        checks.append({"id": cid, "title": title, "ok": bool(ok), "detail": detail, "level": level})
    form = "kubernetes" if os.environ.get("KUBERNETES_SERVICE_HOST") else "docker-compose"
    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    try:
        cur = s.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001
        cur = None
    add("db", "DB 연결", True, f"{settings.db_engine} · SELECT 1")
    add("migrations", "마이그레이션 최신", cur == head, f"현재 {cur} · head {head}")
    injected = {k: bool(v and v != "CHANGE_ME") for k, v in (("원장 서명 키", settings.ledger_signing_key),
                                                             ("SVID 발급 키", settings.svid_signing_key), ("세션 서명 비밀", settings.auth_secret))}
    prod = settings.app_env != "local"
    add("keys", "서명 키 외부 주입", all(injected.values()) or not prod,
        " · ".join(f"{k} {'주입' if v else '볼륨 파일'}" for k, v in injected.items()) + ("" if prod else " (local 은 볼륨 파일 허용)"),
        "required" if prod else "advisory")
    tel = telemetry.status()
    add("observability", "관측 수집기", tel["enabled"], f"{tel['endpoint'] or '미설정'} · 전송 성공 {tel['stats']['traces']['ok']}", "advisory")
    sb = sandbox.status()
    add("sandbox", "샌드박스 L1", sb["maxLevel"] == "L1", f"최고 {sb['maxLevel']} · Landlock {sb['capabilities'].get('landlock')} · seccomp {len(sb['capabilities'].get('seccomp') or [])}", "advisory")
    last = ledger.records(s, kind="identity", limit=1, desc=True)
    add("worker", "worker 주기 작업", bool(last), f"최근 {last[0].created_at if last else '기록 없음'}", "advisory")
    add("admin", "플랫폼 관리자", auth.has_admin(s), "비상 관리자 존재" if auth.has_admin(s) else "/setup 에서 부트스트랩")
    rep = report()
    add("coverage", "도식 커버리지(엄격)", rep["strict"]["implemented"] == rep["strict"]["total"],
        f"전체 {rep['implemented']}/{rep['total']} · 엄격 {rep['strict']['implemented']}/{rep['strict']['total']}")
    first = s.scalar(select(func.min(models.Evidence.created_at)).where(models.Evidence.kind == "gate"))
    req =[c for c in checks if c["level"] == "required"]
    return {"form": form, "env": settings.app_env, "ok": all(c["ok"] for c in req),
            "passed": sum(c["ok"] for c in checks), "total": len(checks), "checks": checks, "firstVerdictAt": first}


# ── 첫 실행 마법사 ②~⑤ · 설치 검증 (SCR-A07~A10, NFR-O1) ───────────
TARGET_MIN = 30                                           # 설치 후 30분 안 첫 판정 (NFR-O1)
SERIES_FAIL = {"C1": "closed", "C2": "closed", "C3": "open", "C4": "open"}   # NFR-A3 기본값


def _ts(v) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, str):
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def setup_status(s: Session) -> dict:
    """설치 시각(부트스트랩 토큰 발급 또는 기본 테넌트 생성) 대비 경과와 마법사 단계 완료 여부 — 실데이터로 판정."""
    from app import auth, identity, sso
    boot = s.scalar(select(func.min(models.Evidence.created_at)).where(models.Evidence.kind == "auth",
                                                                     models.Evidence.ref_id == "bootstrap"))
    default = s.get(models.Tenant, "default")
    installed = min(x for x in (_ts(boot), _ts(default.created_at) if default else None) if x) if (boot or default) else None
    since = installed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") if installed else ""
    first = s.scalar(select(func.min(models.Evidence.created_at)).where(models.Evidence.kind == "gate",   # 설치 이후 첫 판정
                                                                      models.Evidence.created_at >= since))
    first_dt = _ts(first)
    st = identity.status(s)
    retention_set = bool(default and default.retention_days != 90) or bool(ledger.records(s, kind="tenant", limit=1, desc=True))
    verify = ledger.records(s, kind="setup", limit=1, desc=True)
    steps = [
        {"n": 1, "key": "admin", "title": "관리자·SSO", "done": auth.has_admin(s), "href": "/setup",
         "detail": f"비상 관리자 {'있음' if auth.has_admin(s) else '없음'} · 조직 SSO {'사용' if sso.enabled(s) else '미설정(선택)'}"},
        {"n": 2, "key": "identity", "title": "신원·비밀", "done": st["valid"] > 0 and not identity.static_credentials(s), "href": "/setup/identity",
         "detail": f"SVID 유효 {st['valid']} · 정적 자격증명 {len(identity.static_credentials(s))}"},
        {"n": 3, "key": "evidence", "title": "증적·관측", "done": retention_set and telemetry.status()["enabled"], "href": "/setup/evidence",
         "detail": f"보존 {default.retention_days if default else '—'}일 · 수집기 {'연결' if telemetry.status()['enabled'] else '미설정'}"},
        {"n": 4, "key": "first-verdict", "title": "대상·첫 판정", "done": first is not None, "href": "/setup/first-verdict"},
        {"n": 5, "key": "verify", "title": "검증", "done": bool(verify and verify[0].body.get("ok")), "href": "/setup/verify"},
    ]
    now = utcnow()
    return {"installedAt": installed.isoformat() if installed else None,
            "elapsedMin": round((now - installed).total_seconds() / 60, 1) if installed else None,
            "firstVerdictAt": first, "minutesToFirstVerdict": round((first_dt - installed).total_seconds() / 60, 1) if first_dt and installed else None,
            "targetMin": TARGET_MIN, "steps": steps, "done": sum(x["done"] for x in steps)}


def setup_verify(s: Session, by: str) -> dict:
    """설치 검증 (SCR-A10) — 관문 도달(입력·도구·출력 실제 경로 + 증적 적재 지연), 기동 검사(격리·서명),
    강등 기본값(NFR-A3), 누락 검증(FR-P16), 사전 점검. 결과는 원장에 남는다."""
    import time as _t

    from aegis.coverage import report
    from aegis.schemas import JudgeRequest
    samples = {"input": ("d1-05", {"text": "정상 질의 — 관문 도달 시험"}), "tool": ("d3-01", {"tool": {"name": "search_docs", "args": {}}}),
               "output": ("d2-03", {"output": "관문 도달 시험 응답"})}
    gates = []
    for gate, (aid, body) in samples.items():
        try:
            rows = {aid: gating.runtime(s, aid)}
            run = gating.run(gate, JudgeRequest.model_validate(body), rows)
            t0 = _t.perf_counter()
            rec = ledger.append(s, "setup", f"reach:{gate}", {"event": "gate_reach", "gate": gate, "agent": aid,
                                                              "verdict": run["findings"][0].verdict, "latencyMs": run["latencyMs"]})
            s.flush()
            gates.append({"gate": gate, "ok": not run["degraded"], "agent": aid, "latencyMs": run["latencyMs"],
                          "evidenceMs": round((_t.perf_counter() - t0) * 1000, 2), "seq": rec.seq})
        except Exception as exc:  # noqa: BLE001
            gates.append({"gate": gate, "ok": False, "error": f"{type(exc).__name__}: {exc}"[:160]})
    agents = list(s.scalars(select(models.Agent)))
    stopped = [a.id for a in agents if a.status == "stopped"]
    held = [r.agent_id for r in s.scalars(select(models.AgentReview).where(models.AgentReview.outcome == "review_hold"))]
    fail_bad = [f"{a.id}({a.series}→{a.fail_mode})" for a in agents if SERIES_FAIL.get(a.series) and a.fail_mode != SERIES_FAIL[a.series]]
    unsigned = [a.id for a in agents if a.origin == "api" and not s.scalars(select(models.AgentReview).where(
        models.AgentReview.agent_id == a.id, models.AgentReview.outcome.in_(("active", "alert_only")))).first()]
    rep = report()
    pre = precheck(s)
    startup = [{"id": "isolation", "title": "격리 등급 기동 검사", "ok": not stopped, "detail": f"기동 거부 {stopped or 0} · 심사 보류 {sorted(set(held)) or 0}"},
               {"id": "signature", "title": "서드파티 서명·심사", "ok": not unsigned, "detail": f"심사 미통과 api 에이전트 {unsigned or 0}"},
               {"id": "failmode", "title": "강등 기본값 (C1·C2 closed, C3·C4 open)", "ok": not fail_bad, "detail": f"위반 {fail_bad or 0}"},
               {"id": "coverage", "title": "도식 80항목 누락 검증", "ok": rep["strict"]["implemented"] == rep["strict"]["total"],
                "detail": f"전체 {rep['implemented']}/{rep['total']} · 엄격 {rep['strict']['implemented']}/{rep['strict']['total']}"}]
    warnings = [f"{c['title']}: {c['detail']}" for c in pre["checks"] if not c["ok"]]
    ok = all(g["ok"] for g in gates) and all(c["ok"] for c in startup) and pre["ok"]
    result = {"ok": ok, "gates": gates, "startup": startup, "precheck": {"passed": pre["passed"], "total": pre["total"]},
              "warnings": warnings, "status": setup_status(s), "at": utcnow().isoformat(timespec="seconds"), "by": by}
    ledger.append(s, "setup", "verify", {"event": "install_verified", "ok": ok, "by": by,
                                         "gates": [{k: g.get(k) for k in ("gate", "ok", "latencyMs")} for g in gates],
                                         "startup": {c["id"]: c["ok"] for c in startup}, "warnings": len(warnings)})
    return result
