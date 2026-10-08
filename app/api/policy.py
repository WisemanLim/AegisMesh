"""관문·정책 관리 API (FR-P02·P04·P15, SCR-D01~D06·C08) — 정책 버전·diff·단위 시험·롤백(2인 승인),
판정 시뮬레이터(저장 없음), 관문 구성·지연 예산·강등 현황, 사용자 정의 프로파일 검증·저장."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.schemas import JudgeRequest
from app import gates as gates_mod
from app import gating, models, orchestrator, policy, profiles
from app.api.deps import Ctx, ctx, need, read_tenant, session, write_tenant

router = APIRouter(prefix="/v1", tags=["policy"], dependencies=[Depends(ctx)])


def _tenant_read(c: Ctx, tenant: str | None) -> str:
    return read_tenant(c, tenant) or "default"


async def _yaml_body(request: Request) -> dict:
    try:
        raw = yaml.safe_load(await request.body())
    except yaml.YAMLError as exc:
        raise HTTPException(422, f"YAML 파싱 실패: {exc}") from exc
    if not isinstance(raw, dict):
        raise HTTPException(422, "문서는 객체여야 한다")
    return raw


# ── 정책 목록·버전·diff (SCR-D03) ──────────────────────────────
@router.get("/policies")
def list_policies(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = _tenant_read(c, tenant)
    return {"tenant": t, "items": policy.ids(s, t)}


@router.get("/policies/{pid}/versions")
def policy_versions(pid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = _tenant_read(c, tenant)
    rows = policy.versions(s, pid, t)
    if not rows:
        raise HTTPException(404, f"policy {t}/{pid} 없음")
    return {"id": pid, "tenant": t, "items": [{"version": r.version, "createdBy": r.created_by, "createdAt": r.created_at.isoformat(),
                                               "tests": len(r.body.get("tests") or []), "yaml": policy.dump(r.body)} for r in rows]}


@router.get("/policies/{pid}/diff")
def policy_diff(pid: str, from_v: int = Query(alias="from"), to_v: int = Query(alias="to"), tenant: str | None = None,
                s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = _tenant_read(c, tenant)
    by = {r.version: r for r in policy.versions(s, pid, t)}
    if from_v not in by or to_v not in by:
        raise HTTPException(404, f"policy {t}/{pid} 버전 없음")
    return {"id": pid, "tenant": t, "from": from_v, "to": to_v, "diff": policy.diff(by[from_v], by[to_v])}


# ── 단위 시험·배포 전 확인 (SCR-D04) ───────────────────────────
@router.post("/policies:test")
async def test_policy(request: Request, tenant: str | None = None, s: Session = Depends(session),
                      c: Ctx = Depends(need("policy.write"))):
    """초안 정책 YAML 의 tests 를 실제 관문 경로로 재생 — 저장·원장 기록 없음."""
    t = write_tenant(s, c, tenant)
    raw = await _yaml_body(request)
    try:
        doc = policy.parse(raw)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        policy.check_refs(s, doc.spec)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    results = policy.run_tests(s, doc, t)
    cur = policy.latest(s, doc.metadata["id"], t)
    body = policy.body_of(doc)
    return {"tenant": t, "passed": sum(r["ok"] for r in results), "total": len(results), "results": results,
            "diff": policy.diff(cur, models.Policy(policy_id=cur.policy_id, version=cur.version + 1, body=body)) if cur else None}


class RollbackIn(BaseModel):
    to: int = Field(ge=1)
    reason: str = Field(min_length=1)


@router.post("/policies/{pid}:rollback", status_code=202)
def rollback(pid: str, body: RollbackIn, tenant: str | None = None, s: Session = Depends(session),
             c: Ctx = Depends(need("policy.write"))):
    """롤백 요청 → 승인 대기함(2인 승인). 승인 완료 시 해당 버전 본문으로 새 버전이 배포된다."""
    t = write_tenant(s, c, tenant)
    try:
        apr = policy.request_rollback(s, t, pid, body.to, c.name, body.reason)
    except KeyError:
        raise HTTPException(404, f"policy {t}/{pid}@v{body.to} 없음") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    s.commit()
    return {"approvalRef": apr.id, "status": apr.status, "summary": apr.summary, "required": apr.required}


# ── 판정 시뮬레이터 (SCR-D05) ──────────────────────────────────
class SimulateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    gate: str = Field(pattern="^(input|tool|output|offline)$")
    request: JudgeRequest
    agents: list[str] | None = None
    target: str | None = None
    stage: str | None = Field(None, pattern="^(observe|partial|enforce)$")
    policy: str = "default"
    draft: str | None = None                  # 초안 정책 YAML — 배포 정책과 나란히 비교


@router.post("/policies:simulate")
def simulate(body: SimulateIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """실제 차단·기록 없이 관문 합성 판정과 근거를 본다. 판정 경로는 judge:batch 와 같다(gating)."""
    t = write_tenant(s, c, tenant)
    req = body.request.model_copy(update={"trace_id": body.request.trace_id or secrets.token_hex(16),
                                          "subject": body.request.subject.model_copy(update={"tenant": t})})
    try:
        application, rows = gating.bind(s, t, body.agents, body.target)
    except gating.GateError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    stage = body.stage or (application.stage if application else "enforce")
    pol = policy.latest(s, body.policy, t)
    spec = policy.spec_of(pol)
    run = gating.run(body.gate, req, rows, spec)
    deployed, quarantined = gating.decide(s, t, req, run, rows, application, spec, stage)
    out = {"tenant": t, "gate": body.gate, "stage": stage, "simulated": True,
           "profile": application.profile_id if application else None,
           "policy": f"{pol.policy_id}@v{pol.version}" if pol else "builtin-default",
           "latencyMs": run["latencyMs"], "budgetMs": run["budgetMs"], "degraded": run["degraded"],
           "quarantine": quarantined.id if quarantined is not None else None,
           "deployed": deployed, "transformed": run["transformed"], "relocated": run["relocated"],
           "findings": [f.dump() for f in run["findings"]]}
    if body.draft:
        try:
            doc = policy.parse(yaml.safe_load(body.draft))
            policy.check_refs(s, doc.spec)
        except (yaml.YAMLError, ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(422, f"초안 정책: {exc}") from exc
        run2 = run                                       # 설정·재배치가 바뀌면 초안 값으로 다시 실행
        if (doc.spec.agent_params, doc.spec.relocated) != (spec.agent_params, spec.relocated):
            run2 = gating.run(body.gate, req, rows, doc.spec)
            out["draftFindings"] = [f.dump() for f in run2["findings"]]
            out["draftRelocated"] = run2["relocated"]
        draft, _ = gating.decide(s, t, req, run2, rows, application, doc.spec, stage)
        by_agent = lambda dec: {d["agent"]: d for d in dec["decisions"]}   # noqa: E731 — 에이전트당 Finding 1건
        before, after = by_agent(deployed), by_agent(draft)
        out["draft"] = draft
        out["changed"] = [{"ruleId": (after.get(a) or before[a])["ruleId"], "agent": a,
                           "deployed": before[a]["effective"] if a in before else "relocated",
                           "draft": after[a]["effective"] if a in after else "relocated"}
                          for a in sorted(set(before) | set(after))
                          if (before.get(a) or {}).get("effective") != (after.get(a) or {}).get("effective")]
    out["testCase"] = policy.dump({"tests": [{"name": f"sim-{body.gate}-{secrets.token_hex(2)}", "gate": body.gate,
                                              "request": body.request.model_dump(by_alias=True, exclude_none=True, exclude={"trace_id"}),
                                              **({"agents": body.agents} if body.agents else {}),
                                              **({"target": body.target} if body.target else {}),
                                              "expect": (out.get("draft") or deployed)["verdict"]}]})
    return out


# ── 에이전트 설정 (정책 agentParams — 도메인 상세 화면 공통) ─────────────
def _config_agent(s: Session, aid: str):
    try:
        rt, row = gating.runtime(s, aid)
    except gating.GateError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    return rt, row


def _config_out(rt, pol: models.Policy | None, principal: str | None = None) -> dict:
    spec = policy.spec_of(pol)
    cfg = rt.manifest.spec.config
    allv = spec.agent_params.get(rt.id, {})
    per = allv.get("byPrincipal") or {}
    values = per.get(principal, {}) if principal else {k: v for k, v in allv.items() if k != "byPrincipal"}
    item = rt.manifest.item_id
    return {"agent": rt.id, "item": item, "policy": f"{pol.policy_id}@v{pol.version}" if pol else "builtin-default",
            "schema": {k: v.model_dump(by_alias=True, exclude_none=True) for k, v in cfg.items()},
            "values": values, "effective": {k: values.get(k, v.default) for k, v in cfg.items()},
            "rules": rt.rules, "rulesEn": rt.rules_en, "verdicts": rt.manifest.spec.verdicts,
            "overrides": {k: v.model_dump(exclude_none=True) for k, v in spec.overrides.items() if policy.owns_rule(item, k)},
            "minConfidence": spec.min_confidence, "principal": principal, "principals": sorted(per),
            "base": {k: v for k, v in allv.items() if k != "byPrincipal"},
            "relocated": rt.id in spec.relocated,
            "rule": "관문에서는 정책 값이 요청 값보다 우선 — 선언된 설정 키의 호출자 값은 무시(정책에 없으면 엔진 기본값)"}


@router.get("/agents/{aid}/config")
def agent_config(aid: str, policy_id: str = Query("default", alias="policy"), principal: str | None = None, tenant: str | None = None,
                 s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """principal 을 주면 그 보호 대상의 계약 값(byPrincipal) — 관문에서 공통 값보다 우선."""
    t = _tenant_read(c, tenant)
    rt, _ = _config_agent(s, aid)
    return {"tenant": t} | _config_out(rt, policy.latest(s, policy_id, t), principal)


class ConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: dict[str, Any] = {}
    overrides: dict[str, dict[str, Any]] | None = None   # 이 에이전트 항목의 규칙 재정의 {D2-01.rrn: {verdict, threshold}} — 주면 통째로 교체
    policy: str = "default"
    sample: dict[str, Any] | None = None      # 선택 — 이 요청으로 현재·초안 판정을 나란히 본다
    reason: str | None = Field(None, max_length=500)
    principal: str | None = Field(None, max_length=64)   # 보호 대상별 계약(byPrincipal)으로 저장


def _config_draft(s: Session, t: str, aid: str, body: ConfigIn):
    rt, row = _config_agent(s, aid)
    cfg = rt.manifest.spec.config
    unknown = sorted(set(body.values) - set(cfg))
    if unknown:
        raise HTTPException(422, f"{aid}: 선언되지 않은 설정 {unknown} (선언: {sorted(cfg)})")
    bad = [k for k in (body.overrides or {}) if not policy.owns_rule(rt.manifest.item_id, k)]
    if bad:
        raise HTTPException(422, f"{aid}: 다른 항목의 규칙 재정의 {bad} (이 에이전트 = {rt.manifest.item_id})")
    cur = policy.latest(s, body.policy, t)
    raw = policy.with_agent_params(cur, aid, body.values, body.overrides, rt.manifest.item_id, body.principal)
    raw.setdefault("metadata", {})["id"] = body.policy
    try:
        doc = policy.parse(raw)
        policy.check_refs(s, doc.spec)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return rt, row, cur, raw, doc


@router.post("/agents/{aid}/config:test")
def test_agent_config(aid: str, body: ConfigIn, tenant: str | None = None, s: Session = Depends(session),
                      c: Ctx = Depends(need("policy.write"))):
    """변경 시험 — 초안 정책으로 단위 시험 + 코퍼스 영향 + (선택) 표본 판정. 저장·원장 기록 없음."""
    t = write_tenant(s, c, tenant)
    rt, row, cur, raw, doc = _config_draft(s, t, aid, body)
    before = policy.spec_of(cur).agent_params
    results = policy.run_tests(s, doc, t)
    out = {"tenant": t, "agent": aid, "policy": f"{cur.policy_id}@v{cur.version}" if cur else "builtin-default",
           "tests": {"passed": sum(r["ok"] for r in results), "total": len(results), "results": results},
           "impact": policy.config_impact(rt, before, doc.spec.agent_params),
           "diff": policy.diff(cur, models.Policy(policy_id=cur.policy_id, version=cur.version + 1, body=policy.body_of(doc))) if cur else None}
    if body.sample is not None:
        try:
            req = JudgeRequest.model_validate(body.sample)
        except ValueError as exc:
            raise HTTPException(422, f"표본 요청: {exc}") from exc
        req = req.model_copy(update={"gate": row.gate, "subject": req.subject.model_copy(update={"tenant": t})})
        a = rt.judge(orchestrator.agent_request(rt, req, before))
        b = rt.judge(orchestrator.agent_request(rt, req, doc.spec.agent_params))
        out["sample"] = {"current": a.dump(), "draft": b.dump(), "changed": (a.verdict, a.rule_id) != (b.verdict, b.rule_id)}
    out["ok"] = all(r["ok"] for r in results)
    return out


@router.put("/agents/{aid}/config")
def put_agent_config(aid: str, body: ConfigIn, tenant: str | None = None, s: Session = Depends(session),
                     c: Ctx = Depends(need("policy.write"))):
    """배포 — 정책 새 버전(단위 시험 통과 필수). 원장 policy_version 에 사유가 남고, 관문은 캐시 TTL(2초) 안에 반영."""
    t = write_tenant(s, c, tenant)
    if not (body.reason or "").strip():
        raise HTTPException(422, "변경 사유 필요")
    rt, _, cur, raw, _doc = _config_draft(s, t, aid, body)
    try:
        row, results = policy.deploy(s, raw, c.name, t, note=f"agent config {aid}: {body.reason.strip()}")
    except policy.PolicyTestFailed as exc:
        raise HTTPException(422, {"stage": "unit-test", "detail": str(exc), "results": exc.results}) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return {"tenant": t, "changed": cur is None or row.version != cur.version,
            "tests": {"passed": sum(r["ok"] for r in results), "total": len(results)}} | _config_out(rt, row, body.principal)


class InspectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: JudgeRequest
    engine: str | None = None
    policy: str = "default"
    draft: dict[str, Any] | None = None       # 저장 전 설정 값으로 보기(이 에이전트 agentParams 대체)


@router.post("/agents/{aid}:inspect")
def inspect_agent(aid: str, body: InspectIn, tenant: str | None = None, s: Session = Depends(session),
                  c: Ctx = Depends(need("read"))):
    """도메인 상세 화면의 검사기 — 붙여 넣은 요청을 에이전트 하나로 판정하고 엔진 신호·진단(explain)을 돌려준다.
    정책 설정 적용(관문과 같은 병합), 저장·원장 기록 없음(NFR-D1: 원문은 이 응답에만)."""
    t = write_tenant(s, c, tenant)
    rt, row = _config_agent(s, aid)
    spec = policy.spec_of(policy.latest(s, body.policy, t))
    params = spec.agent_params if body.draft is None else spec.agent_params | {aid: body.draft}
    req = body.request.model_copy(update={"gate": row.gate, "trace_id": body.request.trace_id or secrets.token_hex(16),
                                          "subject": body.request.subject.model_copy(update={"tenant": t})})
    req = orchestrator.agent_request(rt, req, params)
    eng = body.engine or rt.manifest.spec.engines.default
    if eng not in rt.engines:
        raise HTTPException(422, f"{aid}: 엔진 {eng} 없음 (사용 가능: {sorted(rt.engines)})")
    f = rt.judge(req, eng)
    adapter = rt.engines[eng]
    sigs = [x.model_dump(by_alias=True, exclude_none=True) for x in adapter.scan(req)] if adapter.module is not None else []
    others = []
    for e in sorted(rt.engines):                      # 엔진이 둘 이상이면 이중 판정(분류기 비교)
        if e != eng:
            g = rt.judge(req, e)
            others.append({"engine": e, "verdict": g.verdict, "confidence": g.confidence, "ruleId": g.rule_id})
    return {"tenant": t, "agent": aid, "item": rt.manifest.item_id, "gate": row.gate, "engine": eng,
            "engines": [{"id": e.id, "kind": e.kind} for e in rt.manifest.spec.engines.available],
            "finding": f.dump(), "signals": sigs, "explain": adapter.explain(req), "others": others,
            "minConfidence": spec.min_confidence, "stored": False}


# ── 관문 구성·지연 예산·강등 현황 (SCR-D01·D02·D06) ───────────────
FAIL_DEFAULTS = {"closed": "타임아웃·오류 시 차단 (C1·C2 — 요청 경로)", "open": "타임아웃·오류 시 통과 + 강등 증적 (C3·C4)"}


def _p95(xs: list[float]) -> float:
    xs = sorted(xs)
    return round(xs[max(0, int(len(xs) * 0.95) - 1)], 3) if xs else 0.0


@router.get("/gates")
def gates(tenant: str | None = None, hours: int = Query(24, ge=1, le=720), s: Session = Depends(session),
          c: Ctx = Depends(need("read"))):
    t = read_tenant(c, tenant)
    apps = select(models.ProfileApplication).where(models.ProfileApplication.active.is_(True))
    if t:
        apps = apps.where(models.ProfileApplication.tenant == t)
    apps_ = list(s.scalars(apps))
    bound = sorted({i for a in apps_ for i in a.agent_ids})
    agents = {a.id: a for a in s.scalars(select(models.Agent).where(models.Agent.id.in_(bound)))} if bound else {}
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fq = select(models.Finding.agent_id, models.Finding.body).where(models.Finding.occurred_at >= since)
    if t:
        fq = fq.where(models.Finding.tenant == t)
    lat: dict[str, list[float]] = {}
    deg: dict[str, int] = {}
    for aid, body in s.execute(fq):
        lat.setdefault(aid, []).append(float(body.get("latencyMs", 0)))
        deg[aid] = deg.get(aid, 0) + bool(body.get("degraded"))
    eq = select(models.Evidence).where(models.Evidence.kind == "gate",
                                       models.Evidence.created_at >= since.isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    if t:
        eq = eq.where(models.Evidence.tenant == t)
    recs = list(s.scalars(eq.order_by(models.Evidence.seq.desc()).limit(5000)))
    factor = orchestrator.timeout_s("input") * 1000 / orchestrator.GATE_BUDGET_MS["input"]
    out = {}
    for g in ("input", "tool", "output", "offline"):
        rs = [r for r in recs if r.body.get("gate") == g]
        budget = orchestrator.GATE_BUDGET_MS.get(g)
        ags = []
        for aid in bound:
            a = agents.get(aid)
            if a is None or a.gate != g:
                continue
            p95 = _p95(lat.get(aid, []))
            ags.append({"id": aid, "nameKo": a.name_ko, "series": a.series, "failMode": a.fail_mode, "status": a.status,
                        "budgetMs": a.latency_budget_ms, "p95Ms": p95, "calls": len(lat.get(aid, [])),
                        "degraded": deg.get(aid, 0), "relocate": bool(budget and lat.get(aid) and p95 > a.latency_budget_ms)})
        out[g] = {"placement": "inline" if budget else "offline (경로 밖, 시간 제한 없음)", "budgetMs": budget,
                  "hardTimeoutMs": round(budget * factor) if budget else None, "parallel": True,
                  "composition": "가장 강한 유효 판정 (block > require_approval > transform > alert > allow)",
                  "agents": ags, "records": len(rs), "p95Ms": _p95([r.body.get("latencyMs", 0) for r in rs]),
                  "overBudget": sum(bool(r.body.get("overBudget")) for r in rs),
                  "degraded": sum(bool(r.body.get("degraded")) for r in rs)}
    degraded_events = [{"seq": r.seq, "at": r.created_at, "gate": r.body.get("gate"), "traceId": r.body.get("traceId"),
                        "agents": r.body.get("degraded"), "verdict": r.body.get("verdict")}
                       for r in recs if r.body.get("degraded")][:50]
    alert_only = [{"id": a.id, "nameKo": a.name_ko, "gate": a.gate}
                  for a in s.scalars(select(models.Agent).where(models.Agent.status == "alert_only"))]
    return {"tenant": t or "*", "hours": hours, "timeoutFactor": factor, "gates": out, "failModes": FAIL_DEFAULTS,
            "alertOnly": alert_only, "degradedEvents": degraded_events,
            "applications": [{"id": a.id, "tenant": a.tenant, "profile": a.profile_id, "target": a.target, "stage": a.stage}
                             for a in apps_],
            "recovery": "경보 전용 강등(alert_only)은 오탐 예산(FP ≤ 0.5%) 회복 후 재심사(R5) 통과 시 active 로 복귀"}


@router.get("/gates:status")
def gates_status(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """상단 바 관문 칩(CMP-15) — 최근 15분 p95·예산, 강등 중이면 closed/open."""
    return gates_mod.status(s, read_tenant(c, tenant))


@router.get("/gates/degradation")
def gates_degradation(tenant: str | None = None, days: int = Query(7, ge=1, le=90), s: Session = Depends(session),
                      c: Ctx = Depends(need("read"))):
    """강등 정책·장애 현황 (SCR-D06) — 현재 강등·경보 전용·failMode·구성요소 실패 동작·자동 강등 규칙·강등 이력(원장)."""
    return gates_mod.degradation(s, read_tenant(c, tenant), days)


@router.get("/gates/{gate}")
def gate_detail(gate: str, tenant: str | None = None, hours: int = Query(24, ge=1, le=720), s: Session = Depends(session),
                c: Ctx = Depends(need("read"))):
    """관문 상세·지연 예산 (SCR-D02) — 에이전트별 p50/p95/p99·예산 몫·지연 분포·재배치 제안·비용·SLO 경보."""
    if gate not in gates_mod.GATES:
        raise HTTPException(404, f"관문 {gate} 없음")
    return gates_mod.detail(s, read_tenant(c, tenant), gate, hours)


class RelocationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent: str
    reason: str = Field(min_length=1, max_length=500)
    restore: bool = False


@router.post("/gates/{gate}/relocations", status_code=202)
def relocate(gate: str, body: RelocationIn, tenant: str | None = None, s: Session = Depends(session),
             c: Ctx = Depends(need("policy.write"))):
    """재배치 적용(또는 restore=인라인 복귀) 요청 → 2인 승인 → 정책 relocated 새 버전."""
    t = write_tenant(s, c, tenant)
    try:
        apr = gates_mod.request_relocation(s, t, gate, body.agent, c.name, body.reason, body.restore)
    except KeyError:
        raise HTTPException(404, f"{gate} 관문 에이전트 {body.agent} 없음") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    s.commit()
    return {"approvalRef": apr.id, "status": apr.status, "required": apr.required, "summary": apr.summary}


@router.post("/gates/{gate}/relocations:ignore")
def ignore_relocation(gate: str, body: RelocationIn, tenant: str | None = None, s: Session = Depends(session),
                      c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    rec = gates_mod.ignore_relocation(s, t, gate, body.agent, c.name, body.reason)
    s.commit()
    return {"ignored": body.agent, "seq": rec.seq}


# ── 사용자 정의 프로파일 (SCR-C08) ─────────────────────────────
@router.post("/profiles:validate")
async def validate_profile(request: Request, tenant: str | None = None, s: Session = Depends(session),
                           c: Ctx = Depends(need("read"))):
    t = read_tenant(c, tenant) or c.scope
    return profiles.validate(s, await _yaml_body(request), t)


@router.post("/profiles", status_code=201)
async def define_profile(request: Request, tenant: str | None = None, s: Session = Depends(session),
                         c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    try:
        row, report = profiles.define(s, await _yaml_body(request), t, c.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return {"id": row.id, "tenant": row.tenant, "nameKo": row.name_ko} | {k: report[k] for k in ("items", "agents", "missing", "warnings")}
