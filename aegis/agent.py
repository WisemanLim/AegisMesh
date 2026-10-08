"""에이전트 로더·실행기 — 매니페스트 + core + engines 를 묶어 Finding 을 만든다 (PRD §8.3)."""
from __future__ import annotations

import importlib.util
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Callable

import yaml

from aegis.manifest import ISOLATION_RANK, Manifest, load_manifest
from aegis.schemas import (
    Action, AgentRef, Decision, EvidenceItem, Finding, JudgeRequest,
)

ROOT = Path(__file__).resolve().parent.parent


def agents_dir() -> Path:
    return Path(os.environ.get("AEGIS_AGENTS_DIR", ROOT / "agents"))


def runtime_isolation() -> str:
    return os.environ.get("AEGIS_RUNTIME_ISOLATION", "L0")


class AgentNotFound(LookupError):
    pass


class StartRefused(RuntimeError):
    """격리 등급 미달 등으로 기동 거부 (PRD §8.6 — 격리를 낮추는 강등 금지)."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class EngineAdapter:
    id: str
    module: ModuleType

    def scan(self, req: JudgeRequest):
        return self.module.scan(req)

    def explain(self, req: JudgeRequest) -> dict | None:
        """선택 진단 훅 — 엔진 모듈에 explain(req) 가 있으면 판정 근거의 구조화 설명(콘솔 상세 화면용, 저장하지 않음)."""
        fn = getattr(self.module, "explain", None) if self.module is not None else None
        return fn(req) if fn else None


@dataclass
class Agent:
    manifest: Manifest
    path: Path
    detect: Callable[[JudgeRequest, EngineAdapter], Decision]
    engines: dict[str, EngineAdapter] = field(default_factory=dict)
    rules: dict[str, str] = field(default_factory=dict)   # ruleId → 설명 (MCP explain·콘솔 근거 뷰)
    rules_en: dict[str, str] = field(default_factory=dict)  # 같은 키의 영어 설명 (rules.en.yaml, NFR-C4) — 한국어가 원문

    @property
    def id(self) -> str:
        return self.manifest.id

    def explain_rule(self, rule_id: str, lang: str = "ko") -> str:
        if lang == "en":
            return self.rules_en.get(rule_id) or self.rules.get(rule_id) or f"Unknown rule: {rule_id}"
        return self.rules.get(rule_id, f"알 수 없는 규칙: {rule_id}")

    def judge(self, req: JudgeRequest, engine: str | None = None) -> Finding:
        spec = self.manifest.spec
        eng_id = engine or spec.engines.default
        t0 = time.perf_counter()
        try:
            eng = self.engines[eng_id]
            decision = self.detect(req, eng)
            if not isinstance(decision, Decision):
                raise TypeError("core.detect 는 Decision 을 반환해야 한다")
        except Exception as exc:  # noqa: BLE001 — 에이전트 장애는 failMode 로 흡수 (NFR-A2)
            return self.degraded(req, f"{type(exc).__name__}: {exc}", (time.perf_counter() - t0) * 1000, eng_id)
        latency = (time.perf_counter() - t0) * 1000
        invalid = None
        if not decision.evidence:
            invalid = "evidence 없음 (DP3)"
        elif decision.verdict not in spec.verdicts:
            invalid = f"매니페스트에 없는 판정 {decision.verdict}"
        if invalid:
            return self.degraded(req, invalid, latency, eng_id, valid=False)
        action = {"block": "blocked", "transform": "transformed", "require_approval": "pending_approval",
                  "alert": "alerted", "allow": "allowed"}[decision.verdict]
        return Finding(
            traceId=req.trace_id or Finding.model_fields["trace_id"].default_factory(),
            agent=AgentRef(id=self.id, version=self.manifest.metadata.version, engine=eng_id),
            subject=req.subject, gate=spec.gate, verdict=decision.verdict,
            confidence=decision.confidence, severity=decision.severity, ruleId=decision.rule_id,
            evidence=decision.evidence, standards=self.standards(),
            action=Action(taken=action, transform=decision.transform), latencyMs=round(latency, 3),
        )

    def standards(self) -> dict:
        return {k: v.model_dump() for k, v in self.manifest.spec.standards.items()}

    def degraded(self, req: JudgeRequest, reason: str, latency: float, engine: str | None = None,
                 valid: bool = True) -> Finding:
        """판정 실패·무효 → failMode 적용 (DP5: C1·C2 는 차단). 강등 사실을 evidence 에 남긴다."""
        closed = self.manifest.spec.fail_mode == "closed"
        return Finding(
            traceId=req.trace_id or Finding.model_fields["trace_id"].default_factory(),
            agent=AgentRef(id=self.id, version=self.manifest.metadata.version,
                           engine=engine or self.manifest.spec.engines.default),
            subject=req.subject, gate=self.manifest.spec.gate,
            verdict="block" if closed else "allow", confidence=0.0,
            severity="high" if closed else "info",
            ruleId=f"{self.manifest.item_id}.{'invalid' if not valid else 'degraded'}",
            evidence=[EvidenceItem(kind="degradation", note=f"fail_{self.manifest.spec.fail_mode}: {reason}")],
            standards=self.standards(),
            action=Action(taken="blocked" if closed else "allowed"),
            latencyMs=round(latency, 3), degraded=True, valid=valid,
            invalidReason=None if valid else reason,
        )


def find_agent_path(agent_id: str) -> Path:
    base = agents_dir()
    exact = base / agent_id
    if (exact / "agent.yaml").exists():
        return exact
    hits = sorted(p for p in base.glob(f"{agent_id.lower()}-*") if (p / "agent.yaml").exists())
    if not hits:
        raise AgentNotFound(agent_id)
    return hits[0]


def load_agent(agent_id_or_path: str | Path) -> Agent:
    path = Path(agent_id_or_path)
    if not (path / "agent.yaml").exists():
        path = find_agent_path(str(agent_id_or_path))
    m = load_manifest(path / "agent.yaml")
    if ISOLATION_RANK[m.spec.isolation] > ISOLATION_RANK[runtime_isolation()]:
        raise StartRefused(f"{m.id}: 요구 격리 {m.spec.isolation} > 런타임 {runtime_isolation()} — 기동 거부")
    prefix = f"aegis_agents.{m.id.replace('-', '_')}"
    core = _load_module(f"{prefix}.core", path / "core.py")
    engines = {}
    for e in m.spec.engines.available:
        if e.kind != "builtin":
            continue  # 외부 엔진(garak 등)은 컨테이너 호출 어댑터 — 후속 단계
        engines[e.id] = EngineAdapter(e.id, _load_module(f"{prefix}.engines.{e.id}", path / "engines" / f"{e.id}.py"))
    return Agent(manifest=m, path=path, detect=core.detect, engines=engines, rules=dict(getattr(core, "RULES", {})),
                 rules_en=rules_en(path))


def rules_en(path: Path) -> dict[str, str]:
    """번들 안 rules.en.yaml (데이터 파일 — 코드 실행 없음). 없으면 빈 사전(콘솔·MCP 가 한국어로 대체)."""
    f = path / "rules.en.yaml"
    data = yaml.safe_load(f.read_text(encoding="utf-8")) if f.exists() else None
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def discover() -> list[Path]:
    return sorted(p.parent for p in agents_dir().glob("*/agent.yaml"))
