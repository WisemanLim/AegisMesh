"""판정·관문·정책·프로파일·판정 조회·승인 API (PRD §12.3)."""
import json
import secrets
from datetime import datetime

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.schemas import JudgeRequest
from app import (approvals, evidence_writer, findings, gating, hotcache, incidents, ledger, models, orchestrator, policy,
                 profiles, registry, samples, telemetry)
from app.api.deps import Ctx, ctx, need, read_tenant, session, visible_or_404, write_tenant

router = APIRouter(prefix="/v1", tags=["judge"], dependencies=[Depends(ctx)])


def _scoped(s: Session, c: Ctx, req: JudgeRequest) -> JudgeRequest:
    """subject.tenant 를 주체 범위로 고정 — 다른 테넌트를 지정하면 403, 생략하면 주체 테넌트(FR-P13)."""
    explicit = "subject" in req.model_fields_set and "tenant" in req.subject.model_fields_set
    tenant = write_tenant(s, c, req.subject.tenant if explicit else None, cached=True)
    return req.model_copy(update={"subject": req.subject.model_copy(update={"tenant": tenant})})


def _runtime(s: Session, agent_id: str):
    try:
        return gating.runtime(s, agent_id)
    except gating.GateError as exc:
        raise HTTPException(exc.status, exc.msg) from exc


# ── 단일 판정 (M1 과 같은 본문) ─────────────────────────────────
@router.post("/judge")
def judge(req: JudgeRequest = Body(...), agent: str = Query(...), engine: str | None = None,
          s: Session = Depends(session), c: Ctx = Depends(need("judge"))):
    req = _scoped(s, c, req)
    rt, _ = _runtime(s, agent)
    spec = hotcache.get(("pol", req.subject.tenant, "default"),
                        lambda: (lambda p: (hotcache.detach(s, p), policy.spec_of(p)))(policy.latest(s, "default", req.subject.tenant)))[1]
    f = rt.judge(orchestrator.agent_request(rt, req, spec.agent_params), engine)
    if evidence_writer.enabled():
        evidence_writer.submit(evidence_writer.Item(f.subject.tenant, f.verdict, [], [(f, None)]))
    else:
        findings.store(s, f)
        s.commit()
    return f.dump()


# ── 관문 판정 (병렬 분배 + 정책 합성) ───────────────────────────
class BatchIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    gate: str = Field(pattern="^(input|tool|output|offline)$")
    request: JudgeRequest
    agents: list[str] | None = None          # 생략 시 활성 프로파일 바인딩
    target: str | None = None
    stage: str | None = Field(None, pattern="^(observe|partial|enforce)$")
    policy: str = "default"


def _gate_judge(s: Session, c: Ctx, gate: str, request: JudgeRequest, agents: list[str] | None, target: str | None,
                stage_: str | None, policy_id: str, stream: dict | None = None) -> tuple[dict, dict, dict]:
    """관문 판정 공통 경로 (judge:batch · judge:stream) — 바인딩 → 병렬 실행 → 정책 합성 → 사건·승인 → 증적(비동기)."""
    who = c.name
    req = _scoped(s, c, request)
    req = req.model_copy(update={"trace_id": req.trace_id or secrets.token_hex(16)})
    tenant, trace = req.subject.tenant, req.trace_id
    try:
        application, rows = gating.bind(s, tenant, agents, target)
    except gating.GateError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    stage = stage_ or (application.stage if application else "enforce")
    pol, spec = hotcache.get(("pol", tenant, policy_id),
                             lambda: (lambda p: (hotcache.detach(s, p), policy.spec_of(p)))(policy.latest(s, policy_id, tenant)))
    run = gating.run(gate, req, rows, spec)
    decision, quarantined = gating.decide(s, tenant, req, run, rows, application, spec, stage)
    eff = {d["findingId"]: d["effective"] for d in decision["decisions"] if d["findingId"]}
    # 스트림 청크는 판정 기록 1건 + 위험 판정만 Finding 으로 남긴다(청크마다 allow Finding 을 쌓지 않음)
    kept = [f for f in run["findings"] if stream is None or eff[f.id] != "allow"]
    if not evidence_writer.enabled():
        for f in kept:
            findings.store(s, f, eff[f.id])
    deferred: list | None = [] if evidence_writer.enabled() else None
    deltas: list | None = [] if evidence_writer.enabled() else None
    opened = incidents.correlate(s, req, run["findings"], eff, deferred, deltas)    # FR-P06 사건 상관 — 열린 사건 덧붙이기는 작성기로


    approval = None
    if decision["verdict"] == "require_approval":
        ids_ = [d["findingId"] for d in decision["decisions"] if d["effective"] == "require_approval"]
        rules = ", ".join(d["ruleId"] for d in decision["decisions"] if d["effective"] == "require_approval")
        requester = (req.subject.principal.id if req.subject.principal else None) or who
        approval = approvals.create(s, trace, tenant, gate, ids_, f"{gate} 관문 승인 요청: {rules}",
                                    requester, records=deferred)
    summary = {"traceId": trace, "gate": gate, "verdict": decision["verdict"], "stage": stage,
               "profile": application.profile_id if application else None,
               "target": application.target if application else None,
               "policy": f"{pol.policy_id}@v{pol.version}" if pol else "builtin-default",
               "agents": [f.agent.id for f in run["findings"]], "degraded": run["degraded"],
               "latencyMs": run["latencyMs"], "budgetMs": run["budgetMs"], "overBudget": run["overBudget"],
               "approvalRef": approval.id if approval else None,
               "quarantine": quarantined.id if quarantined is not None else None,
               "incidents": [i.id for i in opened]} | ({"stream": stream} if stream else {}) \
        | ({"relocated": run["relocated"]} if run["relocated"] else {})
    if stream is None and (cfg := samples.enabled(s, tenant)):          # 미리보기 표본(옵트인·마스킹, OQ1) — 같은 커밋
        samples.capture(s, tenant, cfg, gate, summary["target"], summary["profile"], decision["verdict"], req)
    record = ("gate", trace, summary | {"decisions": decision["decisions"], "shape": gating.shape(req)})
    if evidence_writer.enabled():                                       # NFR-L5 — 요청 경로는 대기열에 넣고 응답
        s.commit()
        evidence = evidence_writer.submit(evidence_writer.Item(tenant, decision["verdict"], [*deferred, record],
                                                               [(f, eff[f.id]) for f in kept], deltas))
    else:
        ledger.append(s, *record, tenant)
        s.commit()
        evidence = "written"
    telemetry.record_gate(gate, tenant, trace, run, decision,
                          {"policy": summary["policy"], "profile": summary["profile"], "stage": stage})
    if run["relocated"]:                                                # 응답 뒤 비동기 판정(차단 불가)
        gating.run_relocated(tenant, gate, req, rows, run["relocated"], spec, stage)
    gating.run_deep(tenant, gate, req, rows, spec, stage, decision["verdict"])   # D1-03 깊은 검사(안전 분류 모델, GUARD_URL 있을 때)
    return summary | {"evidence": evidence}, decision, run


def _json(out: dict) -> Response:
    return Response(json.dumps(out, ensure_ascii=False), media_type="application/json")   # 이미 JSON 형 — 인코더 순회 생략


@router.post("/judge:batch")
def judge_batch(body: BatchIn, s: Session = Depends(session), c: Ctx = Depends(need("judge"))):
    summary, decision, run = _gate_judge(s, c, body.gate, body.request, body.agents, body.target, body.stage, body.policy)
    return _json(summary | {"decisions": decision["decisions"], "findings": [f.dump() for f in run["findings"]],
                            "transformed": run["transformed"]})


HOLDBACK = 128      # 다음 청크까지 내보내지 않고 보류하는 끝부분 길이 — 청크 경계에 걸친 비밀·패턴(키·토큰)을 잡는다


class StreamIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    request: JudgeRequest = JudgeRequest()   # 주체·대상·문맥 (output 은 서버가 보류분+청크로 채운다)
    chunk: str = Field("", max_length=65536)
    held: str = Field("", max_length=4 * HOLDBACK)
    seq: int = Field(0, ge=0)
    streamId: str | None = Field(None, max_length=64)
    final: bool = False
    agents: list[str] | None = None
    target: str | None = None
    stage: str | None = Field(None, pattern="^(observe|partial|enforce)$")
    policy: str = "default"


@router.post("/judge:stream")
def judge_stream(body: StreamIn, s: Session = Depends(session), c: Ctx = Depends(need("judge"))):
    """스트리밍 출력의 청크 단위 판정 (NFR-L3, 출력 관문 예산 150ms/청크).

    청크마다 (보류분 + 청크) 창을 출력 관문으로 판정한다. 변환이면 무해화된 창을, allow·경보면 원래 창을 쓰고,
    끝 HOLDBACK 자는 보류해 다음 청크와 함께 다시 본다(final 이면 모두 내보냄). 차단·승인 필요면 즉시 중단(stop).
    서버는 스트림 상태를 저장하지 않는다 — 보류분은 응답의 held 로 돌려주고 호출자가 다음 요청에 그대로 넣는다."""
    sid = body.streamId or f"str_{secrets.token_hex(8)}"
    window = body.held + body.chunk
    req = body.request.model_copy(update={"output": window})
    summary, decision, run = _gate_judge(s, c, "output", req, body.agents, body.target, body.stage, body.policy,
                                         stream={"id": sid, "seq": body.seq, "final": body.final, "chars": len(body.chunk)})
    v = decision["verdict"]
    if v in ("block", "require_approval"):
        emit, held, stop = "", "", True
    else:
        text = run["transformed"]["value"] if v == "transform" and run["transformed"] else window
        cut = len(text) if body.final else max(0, len(text) - HOLDBACK)
        emit, held, stop = text[:cut], text[cut:], False
    hits = [{"agent": d["agent"], "ruleId": d["ruleId"], "original": d["original"], "effective": d["effective"]}
            for d in decision["decisions"] if d["effective"] != "allow"]
    return _json({"streamId": sid, "seq": body.seq, "final": body.final, "verdict": v, "emit": emit, "held": held, "stop": stop,
                  "hits": hits} | {k: summary[k] for k in ("traceId", "latencyMs", "budgetMs", "overBudget", "approvalRef", "evidence")})


# ── 프로파일 ─────────────────────────────────────────────────
@router.get("/profiles")
def list_profiles(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    rows = [profiles.summary(s, p) | {"tenant": p.tenant, "custom": p.tenant is not None}
            for p in s.scalars(profiles.visible_query(c.scope))]
    return {"items": sorted(rows, key=lambda r: r["order"])}


@router.get("/profiles/{pid}")
def get_profile(pid: str, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    p = s.get(models.Profile, pid)
    if not profiles.visible(p, c.scope):
        raise HTTPException(404, f"profile {pid} 없음")
    return profiles.summary(s, p) | profiles.resolve(s, pid) | {"spec": p.spec, "tenant": p.tenant,
                                                                 "yaml": yaml.safe_dump(p.spec, allow_unicode=True, sort_keys=False)}


class ApplyIn(BaseModel):
    tenant: str | None = None
    target: str = Field(min_length=1)
    stage: str | None = Field(None, pattern="^(observe|partial|enforce)$")


@router.post("/profiles/{pid}:apply", status_code=201)
def apply_profile(pid: str, body: ApplyIn, s: Session = Depends(session), c: Ctx = Depends(need("policy.write"))):
    tenant = write_tenant(s, c, body.tenant)
    if not profiles.visible(s.get(models.Profile, pid), tenant):
        raise HTTPException(404, f"profile {pid} 없음")
    try:
        row = profiles.apply(s, pid, tenant, body.target, body.stage, c.name)
    except KeyError:
        raise HTTPException(404, f"profile {pid} 없음") from None
    s.commit()
    return application_out(row)


@router.get("/applications")
def list_applications(active: bool = True, tenant: str | None = None, s: Session = Depends(session),
                      c: Ctx = Depends(need("read"))):
    q = select(models.ProfileApplication).order_by(models.ProfileApplication.applied_at.desc())
    if t := read_tenant(c, tenant):
        q = q.where(models.ProfileApplication.tenant == t)
    if active:
        q = q.where(models.ProfileApplication.active.is_(True))
    return {"items": [application_out(a) for a in s.scalars(q)]}


@router.post("/applications/{aid}:release")
def release_application(aid: str, s: Session = Depends(session), c: Ctx = Depends(need("policy.write"))):
    a = s.get(models.ProfileApplication, aid)
    visible_or_404(c, a, f"application {aid}")
    try:
        row = profiles.release(s, aid, c.name)
    except KeyError:
        raise HTTPException(404, f"application {aid} 없음") from None
    s.commit()
    s.refresh(row)
    return application_out(row)


def application_out(a: models.ProfileApplication) -> dict:
    return {"id": a.id, "profile": a.profile_id, "tenant": a.tenant, "target": a.target, "stage": a.stage,
            "active": a.active, "agents": a.agent_ids, "missing": a.missing, "appliedBy": a.applied_by,
            "appliedAt": a.applied_at.isoformat()}


# ── 정책 ─────────────────────────────────────────────────────
@router.get("/policies/{pid}")
def get_policy(pid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = read_tenant(c, tenant) or "default"
    row = policy.latest(s, pid, t)
    if not row:
        raise HTTPException(404, f"policy {t}/{pid} 없음")
    return {"id": row.policy_id, "tenant": row.tenant, "version": row.version, "createdBy": row.created_by,
            "createdAt": row.created_at.isoformat(), "body": row.body}


@router.post("/policies", status_code=201)
async def add_policy(request: Request, tenant: str | None = None, s: Session = Depends(session),
                     c: Ctx = Depends(need("policy.write"))):
    t = write_tenant(s, c, tenant)
    try:
        raw = yaml.safe_load(await request.body())
        row, results = policy.deploy(s, raw, c.name, t)          # 단위 시험 실패 → 배포 차단 (SCR-D04)
    except policy.PolicyTestFailed as exc:
        raise HTTPException(422, {"stage": "unit-test", "detail": str(exc), "results": exc.results}) from exc
    except (yaml.YAMLError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return {"id": row.policy_id, "tenant": row.tenant, "version": row.version,
            "tests": {"passed": sum(r["ok"] for r in results), "total": len(results)}}


# ── 판정 조회 ────────────────────────────────────────────────
@router.get("/findings")
def list_findings(trace: str | None = None, agent: str | None = None, verdict: str | None = None,
                  tenant: str | None = None, since: datetime | None = Query(None, alias="from"),
                  limit: int = Query(50, le=500), offset: int = 0, s: Session = Depends(session),
                  c: Ctx = Depends(need("read"))):
    tenant = read_tenant(c, tenant)
    q = select(models.Finding)
    for col, val in ((models.Finding.trace_id, trace), (models.Finding.agent_id, agent),
                     (models.Finding.verdict, verdict), (models.Finding.tenant, tenant)):
        if val:
            q = q.where(col == val)
    if since:
        q = q.where(models.Finding.occurred_at >= since)
    total = s.scalar(select(func.count()).select_from(q.subquery()))
    rows = s.scalars(q.order_by(models.Finding.occurred_at.desc(), models.Finding.id).offset(offset).limit(limit))
    return {"total": total, "items": [r.body for r in rows]}


@router.get("/findings/{fid}")
def get_finding(fid: str, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    row = s.get(models.Finding, fid)
    visible_or_404(c, row, f"finding {fid}")
    ev = s.scalars(select(models.Evidence).where(models.Evidence.kind == "finding",
                                                 models.Evidence.ref_id == fid)).first()
    a = s.get(models.Agent, row.agent_id)
    try:
        rt = registry.runtime_agent(row.agent_id, a.origin) if a else None
        rules, rules_en = (rt.rules, rt.rules_en) if rt else ({}, {})
    except Exception:  # noqa: BLE001 — 설명 조회 실패가 판정 조회를 막지 않는다
        rules, rules_en = {}, {}
    return row.body | {"ledger": ledger.to_dict(ev) if ev else None,
                       "ruleDescription": rules.get(row.rule_id), "ruleDescriptionEn": rules_en.get(row.rule_id)}


# ── 승인 ─────────────────────────────────────────────────────
@router.get("/approvals")
def list_approvals(status: str | None = "pending", tenant: str | None = None, s: Session = Depends(session),
                   c: Ctx = Depends(need("read"))):
    q = select(models.Approval).order_by(models.Approval.created_at.desc())
    if t := read_tenant(c, tenant):
        q = q.where(models.Approval.tenant == t)
    if status:
        q = q.where(models.Approval.status == status)
    return {"items": [approvals.out(s, a) for a in s.scalars(q)]}


class DecideIn(BaseModel):
    decision: str
    reason: str = ""


@router.post("/approvals/{aid}:decide")
def decide(aid: str, body: DecideIn, s: Session = Depends(session), c: Ctx = Depends(need("approve"))):
    a = s.get(models.Approval, aid)
    visible_or_404(c, a, f"approval {aid}")
    try:
        row = approvals.decide(s, aid, c.name, body.decision, body.reason)
    except approvals.ApprovalError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    s.commit()
    return approvals.out(s, row)
