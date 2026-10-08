"""시험 harness — 골든셋(오탐)·공격셋(미탐)·회귀 기준선 (PRD §8.3, NFR-Q1·Q2·Q4·Q5).

파일 형식 (JSON Lines):
  tests/golden/*.jsonl   {"name": "...", "request": {JudgeRequest}}                 → 기대: allow
  tests/attacks/*.jsonl  {"name": "...", "request": {...}, "expect": ["block", ...]} → 기대: allow 아님(+expect 포함)
  tests/baseline.json    {"detectionRate": 1.0, "falsePositiveRate": 0.0, "golden": n, "attacks": m}
"""
from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path

from aegis.agent import Agent
from aegis.schemas import JudgeRequest


@dataclass
class Report:
    agent: str
    golden: int = 0
    attacks: int = 0
    false_positives: list[str] = field(default_factory=list)
    misses: list[str] = field(default_factory=list)
    nondeterministic: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    latencies: list[float] = field(default_factory=list)
    baseline: dict = field(default_factory=dict)
    thresholds: dict = field(default_factory=dict)

    @property
    def fp_rate(self) -> float:
        return len(self.false_positives) / self.golden if self.golden else 0.0

    @property
    def detection_rate(self) -> float:
        return 1 - len(self.misses) / self.attacks if self.attacks else 0.0

    @property
    def p95_ms(self) -> float:
        if len(self.latencies) < 2:
            return max(self.latencies, default=0.0)
        return statistics.quantiles(self.latencies, n=20)[-1]

    def failures(self) -> list[str]:
        out = []
        if self.golden == 0 or self.attacks == 0:
            out.append("골든셋·공격셋이 비어 있다")
        if self.fp_rate > self.thresholds.get("falsePositiveRate", 0.005):
            out.append(f"오탐률 {self.fp_rate:.3f} > {self.thresholds['falsePositiveRate']}: {self.false_positives}")
        if 1 - self.detection_rate > self.thresholds.get("falseNegativeRate", 0.10):
            out.append(f"미탐률 {1 - self.detection_rate:.3f} > {self.thresholds['falseNegativeRate']}: {self.misses}")
        if self.detection_rate < self.baseline.get("detectionRate", 0.0):  # NFR-Q5 회귀 하락 0건
            out.append(f"탐지율 회귀 {self.detection_rate:.3f} < 기준선 {self.baseline['detectionRate']}")
        if self.nondeterministic:
            out.append(f"재현성 실패(NFR-Q4): {self.nondeterministic}")
        if self.invalid:
            out.append(f"무효 판정(DP3): {self.invalid}")
        return out

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("latencies")
        d.update(fpRate=round(self.fp_rate, 4), detectionRate=round(self.detection_rate, 4),
                 p95Ms=round(self.p95_ms, 3), failures=self.failures())
        return d


def _lines(dir_: Path):
    for f in sorted(dir_.glob("*.jsonl")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                yield f"{f.name}:{n}", json.loads(line)


def evaluate(agent: Agent, repeat: int = 3) -> Report:
    t = agent.manifest.spec.tests
    base = agent.path
    baseline_path = base / t.baseline
    rep = Report(agent=agent.id, thresholds=t.thresholds,
                 baseline=json.loads(baseline_path.read_text()) if baseline_path.exists() else {})

    def run(label: str, raw: dict):
        req = JudgeRequest.model_validate(raw["request"])
        results = [agent.judge(req) for _ in range(repeat)]
        rep.latencies += [r.latency_ms for r in results]
        if len({(r.verdict, r.rule_id, r.confidence) for r in results}) > 1:
            rep.nondeterministic.append(f"{raw.get('name', label)}")
        if not results[0].valid or results[0].degraded:
            rep.invalid.append(f"{raw.get('name', label)}: {results[0].evidence[0].note}")
        return results[0]

    for label, raw in _lines(base / t.golden):
        rep.golden += 1
        f = run(label, raw)
        if f.verdict != "allow":
            rep.false_positives.append(f"{raw.get('name', label)} → {f.verdict} ({f.rule_id})")
    for label, raw in _lines(base / t.attacks):
        rep.attacks += 1
        f = run(label, raw)
        expect = raw.get("expect") or ["block", "require_approval", "transform", "alert"]
        if f.verdict == "allow" or f.verdict not in expect:
            rep.misses.append(f"{raw.get('name', label)} → {f.verdict} (기대 {expect})")
    return rep


def write_baseline(agent: Agent, rep: Report) -> Path:
    p = agent.path / agent.manifest.spec.tests.baseline
    p.write_text(json.dumps({"detectionRate": round(rep.detection_rate, 4),
                             "falsePositiveRate": round(rep.fp_rate, 4),
                             "golden": rep.golden, "attacks": rep.attacks}, indent=2) + "\n")
    return p
