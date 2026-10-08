"""프로파일 (M3 즉시 사용, PRD §11.4) — 검증된 에이전트 조합 + 정책 기본값. 적용 = 관문 바인딩."""
from __future__ import annotations

import secrets
from pathlib import Path

import re
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app import ledger, models
from app.policy import STAGES, Override

DIR = Path(__file__).resolve().parent.parent / "profiles"
BINDABLE = ("active", "alert_only")
ISO_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


class Selector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    all: bool = False
    series: list[str] = []
    domain: list[str] = []
    id: list[str] = []


class EvidenceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    retention_days: int | None = Field(None, alias="retentionDays", ge=1, le=3650)
    payload: Literal["none", "masked"] | None = None


class RegionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    model_egress: Literal["allow", "deny"] | None = Field(None, alias="modelEgress")


class ProfileSpec(BaseModel):
    """프로파일 스키마 (SCR-C08 저장 전 검증). 내장 5종도 같은 스키마를 통과한다."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    extends: str | None = None
    select: list[Selector] = []
    policy_overrides: dict[str, Override] = Field({}, alias="policyOverrides")
    evidence: EvidenceSpec | None = None
    region: RegionSpec | None = None
    default_stage: Literal["observe", "partial", "enforce"] = Field("enforce", alias="defaultStage")
    blocking: str | None = None
    expected_latency: str | None = Field(None, alias="expectedLatency")


class ProfileDoc(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    api_version: Literal["aegismesh/v1"] = Field("aegismesh/v1", alias="apiVersion")
    kind: Literal["Profile"] = "Profile"
    metadata: dict
    spec: ProfileSpec


def sync(s: Session) -> int:
    n = 0
    for f in sorted(DIR.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        ProfileDoc.model_validate(doc)
        s.merge(models.Profile(id=doc["metadata"]["id"], name_ko=doc["metadata"]["nameKo"], spec=doc, tenant=None,
                               created_by="builtin"))
        n += 1
    return n


def visible(p: models.Profile | None, tenant: str) -> bool:
    """내장(tenant 없음)은 모두, 사용자 정의는 만든 테넌트만 ('*' = 플랫폼 범위)."""
    return p is not None and (p.tenant is None or tenant in ("*", p.tenant))


def visible_query(tenant: str):
    q = select(models.Profile)
    return q if tenant == "*" else q.where(or_(models.Profile.tenant.is_(None), models.Profile.tenant == tenant))


def _spec(s: Session, pid: str) -> dict:
    p = s.get(models.Profile, pid)
    if not p:
        raise KeyError(pid)
    return p.spec["spec"]


def item_ids(s: Session, pid: str, _seen: frozenset = frozenset()) -> set[str]:
    """선택자(all·series·domain·id)를 도식 항목 ID 집합으로 해석. extends 는 재귀 합집합."""
    if pid in _seen:
        raise ValueError(f"profile extends 순환: {pid}")
    spec = _spec(s, pid)
    items = list(s.scalars(select(models.RiskItem)))
    out = item_ids(s, spec["extends"], _seen | {pid}) if spec.get("extends") else set()
    for sel in spec.get("select", []):
        for it in items:
            if (sel.get("all") or it.series in sel.get("series", []) or (it.domain or "") in sel.get("domain", [])
                    or it.id in sel.get("id", [])):
                out.add(it.id)
    return out


def overrides(s: Session, pid: str) -> dict[str, Override]:
    spec = _spec(s, pid)
    base = overrides(s, spec["extends"]) if spec.get("extends") else {}
    return base | {k: Override.model_validate(v) for k, v in (spec.get("policyOverrides") or {}).items()}


def resolve(s: Session, pid: str) -> dict:
    items = item_ids(s, pid)
    agents = {a.item_id: a for a in s.scalars(select(models.Agent).where(models.Agent.status.in_(BINDABLE)))}
    return {"items": sorted(items), "agents": sorted(agents[i].id for i in items if i in agents),
            "missing": sorted(i for i in items if i not in agents)}


def summary(s: Session, p: models.Profile) -> dict:
    r = resolve(s, p.id)
    sp = p.spec["spec"]
    return {"id": p.id, "nameKo": p.name_ko, "order": p.spec["metadata"].get("order", 99),
            "extends": sp.get("extends"), "items": len(r["items"]), "available": len(r["agents"]),
            "missing": len(r["missing"]), "defaultStage": sp.get("defaultStage", "enforce"),
            "blocking": sp.get("blocking"), "expectedLatency": sp.get("expectedLatency"),
            "evidence": sp.get("evidence"), "region": sp.get("region")}


def apply(s: Session, pid: str, tenant: str, target: str, stage: str | None, by: str) -> models.ProfileApplication:
    spec = _spec(s, pid)
    stage = stage or spec.get("defaultStage", "enforce")
    if stage not in STAGES:
        raise ValueError(f"stage 는 {STAGES} 중 하나")
    r = resolve(s, pid)
    s.execute(update(models.ProfileApplication)
              .where(models.ProfileApplication.tenant == tenant, models.ProfileApplication.target == target,
                     models.ProfileApplication.active.is_(True)).values(active=False))
    row = models.ProfileApplication(id=f"app_{secrets.token_hex(6)}", profile_id=pid, tenant=tenant, target=target,
                                    stage=stage, active=True, agent_ids=r["agents"], missing=r["missing"], applied_by=by)
    s.add(row)
    s.flush()
    ledger.append(s, "profile", row.id, {"event": "profile_applied", "profile": pid, "target": target, "stage": stage,
                                          "agents": r["agents"], "missing": r["missing"], "by": by}, tenant)
    return row


def active_for(s: Session, tenant: str, target: str | None) -> models.ProfileApplication | None:
    q = select(models.ProfileApplication).where(models.ProfileApplication.tenant == tenant,
                                                models.ProfileApplication.active.is_(True))
    if target:
        q = q.where(models.ProfileApplication.target == target)
    return s.scalars(q.order_by(models.ProfileApplication.applied_at.desc()).limit(1)).first()


def release(s: Session, application_id: str, by: str) -> models.ProfileApplication:
    """프로파일 해제 버튼 (PRD §11.1 되돌리기)."""
    row = s.get(models.ProfileApplication, application_id)
    if not row:
        raise KeyError(application_id)
    s.execute(update(models.ProfileApplication).where(models.ProfileApplication.id == application_id)
              .values(active=False))
    ledger.append(s, "profile", application_id, {"event": "profile_released", "by": by}, row.tenant)
    return row


# ── 사용자 정의 프로파일 (SCR-C08) ──────────────────────────────
PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


def validate(s: Session, raw: dict, tenant: str) -> dict:
    """저장 전 검증 — 스키마·extends·선택 결과·판정 값·지연 예산·격리 요구·승인 필요 항목. 저장하지 않는다."""
    errors: list[str] = []
    try:
        doc = ProfileDoc.model_validate(raw)
    except ValidationError as exc:
        return {"ok": False, "errors": [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]}
    meta = doc.metadata
    if not PROFILE_ID.match(str(meta.get("id", ""))):
        errors.append("metadata.id: 소문자로 시작하는 소문자·숫자·- 2~41자")
    if not meta.get("nameKo"):
        errors.append("metadata.nameKo: 표시 이름 필요")
    base = s.get(models.Profile, doc.spec.extends) if doc.spec.extends else None
    if doc.spec.extends and not visible(base, tenant):
        errors.append(f"spec.extends: 프로파일 {doc.spec.extends} 없음")
    items = {i.id: i for i in s.scalars(select(models.RiskItem))}
    unknown = sorted({x for sel in doc.spec.select for x in sel.id if x not in items}
                     | {k.split(".")[0] for k in doc.spec.policy_overrides if k.split(".")[0] not in items})
    if unknown:
        errors.append(f"도식에 없는 항목: {', '.join(unknown)}")
    if errors:
        return {"ok": False, "errors": errors}
    chosen = item_ids(s, doc.spec.extends) if doc.spec.extends else set()
    for sel in doc.spec.select:
        for it in items.values():
            if sel.all or it.series in sel.series or (it.domain or "") in sel.domain or it.id in sel.id:
                chosen.add(it.id)
    agents = {a.item_id: a for a in s.scalars(select(models.Agent).where(models.Agent.status.in_(BINDABLE)))}
    bound = [agents[i] for i in sorted(chosen) if i in agents]
    from app import orchestrator, sandbox
    gates: dict[str, dict] = {}
    for a in bound:
        g = gates.setdefault(a.gate, {"agents": 0, "maxAgentBudgetMs": 0, "gateBudgetMs": orchestrator.GATE_BUDGET_MS.get(a.gate)})
        g["agents"] += 1
        g["maxAgentBudgetMs"] = max(g["maxAgentBudgetMs"], a.latency_budget_ms)
    for g in gates.values():                       # 병렬 분배 — 관문 지연은 가장 느린 에이전트 예산이 지배
        g["withinBudget"] = g["gateBudgetMs"] is None or g["maxAgentBudgetMs"] <= g["gateBudgetMs"]
    rt_iso = sandbox.max_level()
    over_iso = [a.id for a in bound if ISO_RANK[a.isolation] > ISO_RANK[rt_iso]]
    approval_items = sorted(a.item_id for a in bound if "require_approval" in a.manifest["spec"]["verdicts"])
    bad_ov = [k for k, v in doc.spec.policy_overrides.items()
              if v.verdict and (k.split(".")[0] in agents) and v.verdict not in agents[k.split(".")[0]].manifest["spec"]["verdicts"]]
    warnings = [f"{k}: 에이전트가 내지 않는 판정 {doc.spec.policy_overrides[k].verdict} 로 재정의" for k in bad_ov]
    warnings += [f"{g} 관문 예산 초과 가능 (에이전트 예산 {v['maxAgentBudgetMs']}ms > {v['gateBudgetMs']}ms)"
                 for g, v in gates.items() if not v["withinBudget"]]
    if over_iso:
        warnings.append(f"격리 {rt_iso} 런타임에서 기동 불가: {', '.join(over_iso)}")
    missing = sorted(i for i in chosen if i not in agents)
    return {"ok": True, "errors": [], "warnings": warnings, "id": f"{tenant}.{meta['id']}" if tenant != "*" else meta["id"],
            "items": sorted(chosen), "agents": [a.id for a in bound], "missing": missing, "gates": gates,
            "approvalItems": approval_items, "isolation": {"runtime": rt_iso, "overRuntime": over_iso},
            "defaultStage": doc.spec.default_stage}


def define(s: Session, raw: dict, tenant: str, by: str) -> tuple[models.Profile, dict]:
    """테넌트 사용자 정의 프로파일 저장(id = <tenant>.<id>). 내장 프로파일은 바꿀 수 없다."""
    if tenant == "*":
        raise ValueError("사용자 정의 프로파일은 테넌트 범위에서 만든다 (X-Aegis-Tenant)")
    report = validate(s, raw, tenant)
    if not report["ok"]:
        raise ValueError("; ".join(report["errors"]))
    pid = report["id"]
    existing = s.get(models.Profile, pid)
    if existing is not None and existing.tenant != tenant:
        raise ValueError(f"프로파일 {pid} 를 바꿀 수 없다")
    doc = dict(raw)
    doc["metadata"] = {**raw["metadata"], "id": pid}
    s.merge(models.Profile(id=pid, name_ko=raw["metadata"]["nameKo"], spec=doc, tenant=tenant, created_by=by))
    s.flush()
    ledger.append(s, "profile", pid, {"event": "profile_defined", "by": by, "items": len(report["items"]),
                                      "agents": len(report["agents"]), "missing": report["missing"],
                                      "updated": existing is not None}, tenant)
    return s.get(models.Profile, pid), report
