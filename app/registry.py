"""레지스트리 (FR-P03) — 도식 항목·에이전트 동기화, 매니페스트 등록(R1), 런타임 에이전트 캐시."""
from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import agent as rt
from aegis.coverage import load_diagram
from aegis.harness import evaluate
from aegis.manifest import Manifest, load_manifest
from app import models
from app.core.config import settings

log = logging.getLogger("aegismesh.registry")


class RegistrationError(ValueError):
    def __init__(self, stage: str, detail):
        super().__init__(f"{stage}: {detail}")
        self.stage, self.detail = stage, detail


def sync_risk_items(s: Session) -> int:
    d = load_diagram()
    rows = [dict(id=i["id"], kind="item", domain=i["domain"], name_en=i["nameEn"], name_ko=i["nameKo"],
                 priority=i["priority"], series=i["series"], stage=i["stage"], fr=i["fr"]) for i in d["items"]]
    rows += [dict(id=g["id"], kind="gap", domain=None, name_en=g["nameEn"], name_ko=g["nameKo"],
                  priority=g["priority"], series=g["series"], stage=g["stage"], fr=g["fr"]) for g in d["gaps"]]
    for r in rows:
        s.merge(models.RiskItem(**r))
    return len(rows)


def _row(m: Manifest, origin: str, status: str) -> models.Agent:
    sp = m.spec
    return models.Agent(id=m.id, item_id=m.item_id, version=m.metadata.version, name=m.metadata.name,
                        name_ko=m.metadata.name_ko, series=sp.series, gate=sp.gate, isolation=sp.isolation,
                        fail_mode=sp.fail_mode, latency_budget_ms=sp.latency_budget_ms, status=status,
                        origin=origin, manifest=m.model_dump(by_alias=True, mode="json"))


def sync_builtin_agents(s: Session) -> list[str]:
    """agents/ 디렉터리의 내장 에이전트를 등록. 기동 불가(격리 미달 등)면 stopped."""
    loaded = []
    for path in rt.discover():
        m = load_manifest(path / "agent.yaml")
        try:
            runtime_agent(m.id)
            status = "active"
        except rt.StartRefused as exc:
            log.warning("%s", exc)
            status = "stopped"
        existing = s.get(models.Agent, m.id)
        if existing is not None and existing.origin == "api":
            log.warning("%s: 심사를 통과한 서드파티 에이전트가 담당 — 내장 동기화 건너뜀 (DP1)", m.id)
            continue
        row = _row(m, "builtin", status if not existing or existing.status != "alert_only" else "alert_only")
        s.merge(row)
        loaded.append(m.id)
    return loaded


def register(s: Session, raw: dict) -> tuple[models.Agent, dict]:
    """등록 7단계 중 R1(매니페스트 검증)을 수행. R2~R5 는 심사 파이프라인(후속) — review_pending 으로 둔다."""
    try:
        m = Manifest.model_validate(raw)
    except ValidationError as exc:
        raise RegistrationError("R1", exc.errors(include_url=False, include_context=False)) from exc
    if not s.get(models.RiskItem, m.item_id):
        raise RegistrationError("R1", f"도식에 없는 항목 {m.item_id}")
    existing = s.get(models.Agent, m.id)
    if existing and existing.origin == "builtin":
        raise RegistrationError("R1", f"{m.id} 는 내장 에이전트가 이미 담당한다 (DP1 항목당 에이전트 하나)")
    row = _row(m, "api", "review_pending")
    s.merge(row)
    review = {"R1": "passed", "R2": "pending", "R3": "pending", "R4": "pending", "R5": "pending",
              "note": "서명·정적 심사·격리 시험·품질 판정 파이프라인은 후속 단계. 심사 전에는 관문에 바인딩되지 않는다."}
    return row, review


@lru_cache(maxsize=256)
def _runtime(agent_id: str, origin: str) -> rt.Agent:
    if origin == "api":
        from app import sandbox
        from app.review import registry_dir
        path = (registry_dir() / agent_id / "current").resolve()
        m = load_manifest(path / "agent.yaml")
        if m.spec.isolation in ("L1", "L2", "L3"):   # 코드는 요구 등급의 격리 안에서만 적재·실행 (FR-P08) — L2 = gVisor 브로커(Epic 65)
            if not sandbox.available(m.spec.isolation):
                raise rt.StartRefused(f"{m.id}: 요구 격리 {m.spec.isolation} — 실행 환경 없음 (격리 강등 금지)")
            return sandbox.sandboxed_agent(path, m)
        return rt.load_agent(path)
    ag = rt.load_agent(agent_id)
    eng = engine_overrides().get(agent_id)
    if eng and eng in ag.engines:                    # 배치 설정 — 예: make injguard-up 이 d1-03=injection_model (Epic 64)
        ag.manifest.spec.engines.default = eng
    return ag


def engine_overrides() -> dict[str, str]:
    """ENGINE_OVERRIDES="d1-03=injection_model,…" → {에이전트: 기본 엔진}. 없는 엔진은 무시(매니페스트 기본 유지)."""
    return dict(x.split("=", 1) for x in (settings.engine_overrides or "").replace(" ", "").split(",") if "=" in x)


def runtime_agent(agent_id: str, origin: str = "builtin") -> rt.Agent:
    """builtin = agents/ 디렉터리, api = 심사(R1~R5)를 통과해 registry_dir 에 풀린 서드파티 번들.
    캐시 키를 (id, origin) 위치 인자로 고정 — 기본값 호출과 명시 호출이 같은 인스턴스를 받는다."""
    return _runtime(agent_id, origin)


runtime_agent.cache_clear = _runtime.cache_clear  # type: ignore[attr-defined]


@lru_cache(maxsize=256)
def quality(agent_id: str) -> dict:
    """실측 품질 지표 — 골든셋·공격셋 재생 (GET /v1/agents/{id})."""
    rep = evaluate(runtime_agent(agent_id), repeat=1)
    return {"golden": rep.golden, "attacks": rep.attacks, "falsePositiveRate": round(rep.fp_rate, 4),
            "detectionRate": round(rep.detection_rate, 4), "p95Ms": round(rep.p95_ms, 3),
            "baseline": rep.baseline, "pass": not rep.failures()}


def agents(s: Session) -> list[models.Agent]:
    return list(s.scalars(select(models.Agent).order_by(models.Agent.id)))
