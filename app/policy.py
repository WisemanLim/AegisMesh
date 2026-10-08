"""정책 결정점 (FR-P02, DP6) — 내장 선언형 YAML 평가기.

결정 함수 `evaluate()` 는 순수 함수다. 평가 엔진을 OPA 등으로 바꿀 때 이 함수만 교체한다(DP8).

정책 문서 형식:
  apiVersion: aegismesh/v1
  kind: Policy
  metadata: {id: default}
  spec:
    minConfidence: 0.5            # 이 미만의 block·require_approval 은 alert 로 낮춘다
    partialBlockConfidence: 0.9   # stage=partial 에서 차단을 유지할 최소 신뢰도
    overrides:                    # 항목(D2-01) 또는 규칙(D2-01.rrn) 단위
      D2-01: {verdict: block, threshold: 0.6}
    agentParams:                  # 에이전트 설정(매니페스트 spec.config 선언 키만) — 관문에서 요청 값보다 우선
      d1-06: {urlAllowlist: [cdn.example.com]}
    relocated: [d4-01]            # 지연 예산 초과 → 상시 계열(응답 후 비동기 판정, 차단 불가)로 재배치
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.schemas import VERDICT_RANK, Finding, Verdict
from app import models

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"
STAGES = ("observe", "partial", "enforce")


class Override(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Verdict | None = None
    threshold: float | None = Field(None, ge=0, le=1)


class Budgets(BaseModel):
    """방어 비용·SLO 예산 (SCR-D02 비용·SLO 경보, X10) — 단가를 넣어야 비용을 계산·경보한다(추정치를 지어내지 않음)."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    cost_per_1k: float | None = Field(None, alias="costPer1k", ge=0)          # 관문 판정 1천 건당 방어 비용(원)
    monthly_budget: float | None = Field(None, alias="monthlyBudget", ge=0)   # 월 방어 비용 예산(원)
    alert_ratio: float = Field(0.8, alias="alertRatio", gt=0, le=1)
    over_streak: int = Field(3, alias="overStreak", ge=1)                     # 관문·에이전트 p95 예산 초과 연속 일수 → 경보·재배치 제안


class PolicySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    min_confidence: float = Field(0.5, alias="minConfidence", ge=0, le=1)
    partial_block_confidence: float = Field(0.9, alias="partialBlockConfidence", ge=0, le=1)
    overrides: dict[str, Override] = {}
    agent_params: dict[str, dict[str, Any]] = Field({}, alias="agentParams")
    relocated: list[str] = []
    budgets: Budgets | None = None


class PolicyTest(BaseModel):
    """정책 단위 시험 (SCR-D04·D05) — 배포 전에 실제 관문 경로로 재생, 하나라도 다르면 배포를 막는다."""
    model_config = ConfigDict(extra="forbid")
    name: str
    gate: str = Field(pattern="^(input|tool|output|offline)$")
    request: dict[str, Any] = {}
    agents: list[str] | None = None          # 생략 시 테넌트 활성 프로파일 바인딩
    target: str | None = None
    stage: str | None = Field(None, pattern="^(observe|partial|enforce)$")
    expect: Verdict


class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    api_version: str = Field("aegismesh/v1", alias="apiVersion")
    kind: str = "Policy"
    metadata: dict[str, Any]
    spec: PolicySpec
    tests: list[PolicyTest] = []


def _lower(verdict: str, to: str, reason: str, reasons: list[str]) -> str:
    if VERDICT_RANK[to] < VERDICT_RANK[verdict]:
        reasons.append(reason)
        return to
    return verdict


def effective(f: Finding, spec: PolicySpec, stage: str, extra: dict[str, Override] | None = None,
              alert_only: bool = False) -> tuple[str, list[str]]:
    """판정 하나에 정책·단계를 적용한 유효 판정과 사유."""
    v, reasons = f.verdict, []
    item = f.rule_id.split(".")[0]
    ov = (extra or {}).get(f.rule_id) or (extra or {}).get(item) or spec.overrides.get(f.rule_id) or spec.overrides.get(item)
    if ov and v != "allow" and not f.degraded:
        if ov.verdict and ov.verdict != v:
            reasons.append(f"override {item}: {v}→{ov.verdict}")
            v = ov.verdict
        if ov.threshold is not None and f.confidence < ov.threshold:
            v = _lower(v, "alert", f"override threshold {ov.threshold}", reasons)
    if v in ("block", "require_approval") and not f.degraded and f.confidence < spec.min_confidence:
        v = _lower(v, "alert", f"confidence {f.confidence} < minConfidence {spec.min_confidence}", reasons)
    if alert_only:
        v = _lower(v, "alert", "agent alert_only (오탐 예산 강등)", reasons)
    if stage == "observe":
        v = _lower(v, "alert", "stage observe (관측만)", reasons)
    elif stage == "partial" and v in ("block", "require_approval") and f.confidence < spec.partial_block_confidence:
        v = _lower(v, "alert", f"stage partial: confidence < {spec.partial_block_confidence}", reasons)
    return v, reasons


def evaluate(findings: list[Finding], spec: PolicySpec, stage: str,
             extra: dict[str, Override] | None = None, alert_only: frozenset[str] = frozenset()) -> dict:
    rows = []
    for f in findings:
        v, why = effective(f, spec, stage, extra, f.agent.id in alert_only)
        rows.append({"findingId": f.id, "agent": f.agent.id, "ruleId": f.rule_id, "original": f.verdict,
                     "effective": v, "reasons": why, "degraded": f.degraded})
    final = max((r["effective"] for r in rows), key=VERDICT_RANK.__getitem__, default="allow")
    return {"verdict": final, "decisions": rows}


# ── 저장 (버전 관리) ─────────────────────────────────────────
def parse(raw: dict) -> PolicyDoc:
    doc = PolicyDoc.model_validate(raw)
    if not doc.metadata.get("id"):
        raise ValueError("metadata.id 필요")
    return doc


def body_of(doc: PolicyDoc) -> dict:
    """저장 본문 — 빈 tests·agentParams·relocated 는 뺀다(이전 판본과 같은 본문이면 새 버전을 만들지 않게)."""
    body = doc.model_dump(by_alias=True, mode="json")
    if not body["tests"]:
        body.pop("tests")
    for k in ("agentParams", "relocated", "budgets"):
        if not body["spec"][k]:
            body["spec"].pop(k)
    return body


INLINE_GATES = ("input", "tool", "output")


def check_refs(s: Session, spec: PolicySpec) -> None:
    """agentParams·relocated 를 레지스트리 매니페스트와 대조 — 선언 안 된 키·형 불일치·없는 에이전트는 ValueError."""
    from aegis.manifest import ConfigParam, check_param
    ids = set(spec.agent_params) | set(spec.relocated)
    if not ids:
        return
    rows = {a.id: a for a in s.scalars(select(models.Agent).where(models.Agent.id.in_(ids)))}
    errs = []
    for aid, values in spec.agent_params.items():
        a = rows.get(aid)
        if a is None:
            errs.append(f"agentParams.{aid}: 에이전트 없음")
            continue
        cfg = (a.manifest.get("spec") or {}).get("config") or {}
        per = values.get("byPrincipal")
        if per is not None:
            if not isinstance(per, dict) or not all(isinstance(x, dict) for x in per.values()):
                errs.append(f"agentParams.{aid}.byPrincipal: {{주체: {{설정}}}} 형태여야 한다")
                per = {}
            for pid, sub in per.items():
                for k, v in sub.items():
                    if k not in cfg:
                        errs.append(f"agentParams.{aid}.byPrincipal.{pid}.{k}: 선언되지 않은 설정")
                    elif (e := check_param(ConfigParam.model_validate(cfg[k]), v)):
                        errs.append(f"agentParams.{aid}.byPrincipal.{pid}.{k}: {e}")
        for k, v in values.items():
            if k == "byPrincipal":
                continue
            if k not in cfg:
                errs.append(f"agentParams.{aid}.{k}: 매니페스트에 선언되지 않은 설정 (선언: {', '.join(cfg) or '없음'})")
            elif (e := check_param(ConfigParam.model_validate(cfg[k]), v)):
                errs.append(f"agentParams.{aid}.{k}: {e}")
    for aid in spec.relocated:
        a = rows.get(aid)
        if a is None:
            errs.append(f"relocated.{aid}: 에이전트 없음")
        elif a.gate not in INLINE_GATES:
            errs.append(f"relocated.{aid}: 인라인 관문 에이전트만 재배치 가능 (현재 {a.gate})")
    if errs:
        raise ValueError("; ".join(errs))


def latest(s: Session, policy_id: str = "default", tenant: str = "default") -> models.Policy | None:
    """테넌트 네임스페이스 안에서만 찾는다 — 다른 테넌트 정책은 절대 반환하지 않는다(FR-P13)."""
    return s.scalars(select(models.Policy).where(models.Policy.tenant == tenant, models.Policy.policy_id == policy_id)
                     .order_by(models.Policy.version.desc()).limit(1)).first()


def add_version(s: Session, raw: dict, by: str, tenant: str = "default", note: str | None = None) -> models.Policy:
    doc = parse(raw)
    check_refs(s, doc.spec)
    pid = doc.metadata["id"]
    cur = latest(s, pid, tenant)
    body = body_of(doc)
    if cur and cur.body == body:
        return cur
    row = models.Policy(tenant=tenant, policy_id=pid, version=(cur.version + 1) if cur else 1, body=body, created_by=by)
    s.add(row)
    s.flush()
    from app import ledger
    ledger.append(s, "policy", f"{pid}@v{row.version}", {"event": "policy_version", "by": by, "body": body}
                  | ({"note": note} if note else {}), tenant)
    return row


def ensure_default(s: Session, tenant: str = "default") -> str:
    row = add_version(s, yaml.safe_load(DEFAULT_PATH.read_text(encoding="utf-8")), "system", tenant)
    return f"{row.policy_id}@v{row.version}"


def spec_of(row: models.Policy | None) -> PolicySpec:
    return PolicySpec.model_validate(row.body["spec"]) if row else PolicySpec()


# ── 단위 시험·버전·diff·롤백 (SCR-D03·D04) ─────────────────────
class PolicyTestFailed(ValueError):
    def __init__(self, results: list[dict]):
        super().__init__("정책 단위 시험 실패 — 배포 차단")
        self.results = results


def run_tests(s: Session, doc: PolicyDoc, tenant: str) -> list[dict]:
    """초안 정책으로 시험 케이스를 실제 관문 경로(gating)로 재생. 저장·원장 기록 없음."""
    import secrets as _secrets

    from aegis.schemas import JudgeRequest
    from app import gating
    spec = doc.spec
    out = []
    for case in doc.tests:
        try:
            req = JudgeRequest.model_validate(case.request)
            req = req.model_copy(update={"trace_id": req.trace_id or _secrets.token_hex(16),
                                         "subject": req.subject.model_copy(update={"tenant": tenant})})
            application, rows = gating.bind(s, tenant, case.agents, case.target)
            run_ = gating.run(case.gate, req, rows, spec)
            stage = case.stage or (application.stage if application else "enforce")
            decision, _ = gating.decide(s, tenant, req, run_, rows, application, spec, stage)
            got = decision["verdict"]
            out.append({"name": case.name, "gate": case.gate, "expect": case.expect, "got": got, "ok": got == case.expect,
                        "rules": [d["ruleId"] for d in decision["decisions"] if d["effective"] != "allow"]})
        except Exception as exc:  # noqa: BLE001 — 시험 하나의 오류는 그 시험의 실패로 남긴다
            out.append({"name": case.name, "gate": case.gate, "expect": case.expect, "got": None, "ok": False,
                        "error": getattr(exc, "msg", None) or str(exc)})
    return out


def deploy(s: Session, raw: dict, by: str, tenant: str, note: str | None = None) -> tuple[models.Policy, list[dict]]:
    """새 버전 배포 = 참조 검증·단위 시험 통과 후 add_version. 실패하면 ValueError·PolicyTestFailed (저장하지 않음)."""
    doc = parse(raw)
    check_refs(s, doc.spec)
    results = run_tests(s, doc, tenant)
    if any(not r["ok"] for r in results):
        raise PolicyTestFailed(results)
    return add_version(s, raw, by, tenant, note), results


def versions(s: Session, policy_id: str, tenant: str) -> list[models.Policy]:
    return list(s.scalars(select(models.Policy).where(models.Policy.tenant == tenant, models.Policy.policy_id == policy_id)
                          .order_by(models.Policy.version.desc())))


def ids(s: Session, tenant: str) -> list[dict]:
    rows: dict[str, list[models.Policy]] = {}
    for p in s.scalars(select(models.Policy).where(models.Policy.tenant == tenant).order_by(models.Policy.version)):
        rows.setdefault(p.policy_id, []).append(p)
    return [{"id": k, "tenant": tenant, "version": v[-1].version, "versions": len(v), "createdBy": v[-1].created_by,
             "createdAt": v[-1].created_at.isoformat(), "tests": len(v[-1].body.get("tests") or []),
             "overrides": len(v[-1].body["spec"].get("overrides") or {}),
             "agentParams": len(v[-1].body["spec"].get("agentParams") or {}),
             "relocated": len(v[-1].body["spec"].get("relocated") or [])} for k, v in sorted(rows.items())]


def dump(body: dict) -> str:
    return yaml.safe_dump(body, allow_unicode=True, sort_keys=False)


def diff(a: models.Policy, b: models.Policy) -> str:
    import difflib
    return "".join(difflib.unified_diff(dump(a.body).splitlines(keepends=True), dump(b.body).splitlines(keepends=True),
                                        f"{a.policy_id}@v{a.version}", f"{b.policy_id}@v{b.version}"))


def request_rollback(s: Session, tenant: str, policy_id: str, to: int, by: str, reason: str) -> models.Approval:
    """롤백은 2인 승인 후 적용(SCR-D03) — 승인 완료 시 해당 버전 본문으로 새 버전을 만든다(이력은 지우지 않음)."""
    import secrets as _secrets

    from app import approvals
    cur = latest(s, policy_id, tenant)
    target = next((p for p in versions(s, policy_id, tenant) if p.version == to), None)
    if cur is None or target is None:
        raise KeyError(f"{policy_id}@v{to}")
    if cur.version == to:
        raise ValueError(f"이미 v{to} 가 최신")
    return approvals.create(s, _secrets.token_hex(16), tenant, "policy", [],
                            f"정책 롤백 {policy_id} v{cur.version} → v{to}: {reason}", by,
                            action={"type": "policy_rollback", "policy": policy_id, "from": cur.version, "to": to})


def apply_action(s: Session, approval: models.Approval) -> dict:
    """승인 완료된 행동 실행 (approvals.decide 가 호출)."""
    act = approval.action or {}
    if act.get("type") == "policy_rollback":
        target = next(p for p in versions(s, act["policy"], approval.tenant) if p.version == act["to"])
        row = add_version(s, dict(target.body), f"approval:{approval.id}", approval.tenant)
        return {"applied": "policy_rollback", "policy": f"{row.policy_id}@v{row.version}", "from": act["from"], "to": act["to"]}
    if act.get("type") in ("gate_relocate", "gate_restore"):          # SCR-D02 재배치 적용·되돌림(2인 승인)
        cur = latest(s, act.get("policy", "default"), approval.tenant)
        raw = dict(cur.body) if cur else yaml.safe_load(DEFAULT_PATH.read_text(encoding="utf-8"))
        raw["spec"] = dict(raw["spec"])
        moved = [a for a in raw["spec"].get("relocated", []) if a != act["agent"]]
        if act["type"] == "gate_relocate":
            moved.append(act["agent"])
        raw["spec"]["relocated"] = sorted(moved)
        row = add_version(s, raw, f"approval:{approval.id}", approval.tenant, note=f"{act['type']} {act['agent']} ({act.get('gate')})")
        return {"applied": act["type"], "policy": f"{row.policy_id}@v{row.version}", "agent": act["agent"]}
    raise ValueError(f"알 수 없는 승인 행동 {act.get('type')}")


# ── 에이전트 설정 (도메인 상세 화면 공통 — 정책 agentParams) ───────────────
def owns_rule(item: str, key: str) -> bool:
    return key == item or key.startswith(item + ".")


def with_agent_params(cur: models.Policy | None, agent_id: str, values: dict[str, Any],
                      overrides: dict[str, dict] | None = None, item: str | None = None, principal: str | None = None) -> dict:
    """현재 정책 본문에 에이전트 하나의 설정을 바꿔 넣은 초안. 값이 None·빈 값이면 그 키를 지운다(엔진 기본값).
    overrides 를 주면 이 에이전트 항목(item, 예 D2-01)의 규칙 재정의를 통째로 바꾼다(다른 항목 재정의는 유지)."""
    import copy
    raw = copy.deepcopy(cur.body) if cur else yaml.safe_load(DEFAULT_PATH.read_text(encoding="utf-8"))
    if overrides is not None and item:
        keep = {k: v for k, v in (raw["spec"].get("overrides") or {}).items() if not owns_rule(item, k)}
        raw["spec"]["overrides"] = keep | {k: {f: x for f, x in v.items() if x is not None} for k, v in overrides.items()
                                           if any(x is not None for x in v.values())}
    ap = raw["spec"].setdefault("agentParams", {})
    vals = {k: v for k, v in values.items() if v is not None and v != ""}
    if principal:                                        # 보호 대상별 계약 — 공통 값은 그대로, byPrincipal[주체] 만 교체
        cur_a = dict(ap.get(agent_id) or {})
        per = dict(cur_a.get("byPrincipal") or {})
        if vals:
            per[principal] = vals
        else:
            per.pop(principal, None)
        cur_a = {k: v for k, v in cur_a.items() if k != "byPrincipal"} | ({"byPrincipal": per} if per else {})
        vals = cur_a
    else:
        keep = (ap.get(agent_id) or {}).get("byPrincipal")
        vals = vals | ({"byPrincipal": keep} if keep else {})
    if vals:
        ap[agent_id] = vals
    else:
        ap.pop(agent_id, None)
    if not ap:
        raw["spec"].pop("agentParams")
    return raw


def config_impact(rt, before: dict[str, dict], after: dict[str, dict], limit: int = 20) -> dict:
    """설정 변경 영향 — 에이전트 골든(정상)·공격 코퍼스를 현재 값과 초안 값으로 재생해 판정이 바뀐 표본을 센다.
    표본의 시나리오 params 는 두고 정책 값만 덮는다(strict=False). 저장 없음."""
    from aegis.harness import _lines
    from aegis.schemas import JudgeRequest
    from app import orchestrator
    t = rt.manifest.spec.tests
    out = {"golden": {"total": 0, "flaggedBefore": 0, "flaggedAfter": 0},
           "attacks": {"total": 0, "detectedBefore": 0, "detectedAfter": 0}, "changed": []}
    for label, d in (("golden", rt.path / t.golden), ("attacks", rt.path / t.attacks)):
        if not d.exists():
            continue
        for ref, raw in _lines(d):
            req = JudgeRequest.model_validate(raw["request"])
            a = rt.judge(orchestrator.agent_request(rt, req, before, strict=False)).verdict
            b = rt.judge(orchestrator.agent_request(rt, req, after, strict=False)).verdict
            row = out[label]
            row["total"] += 1
            k = "flagged" if label == "golden" else "detected"
            row[k + "Before"] += a != "allow"
            row[k + "After"] += b != "allow"
            if a != b and len(out["changed"]) < limit:
                out["changed"].append({"set": label, "name": raw.get("name") or ref, "before": a, "after": b})
    return out
