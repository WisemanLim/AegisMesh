"""core 공통 판정 헬퍼 — 신호 목록을 Decision 으로 바꾼다. 순수 함수(네트워크·전역 상태 없음)."""
from __future__ import annotations

from typing import Callable

from aegis.engine import Signal
from aegis.schemas import VERDICT_RANK, Decision, EvidenceItem

_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def decide(item: str, signals: list[Signal], verdict_of: dict[str, str], *, rules: int,
           transform: Callable[[list[Signal]], str | None] | None = None,
           min_score: float = 0.5) -> Decision:
    """item: 도식 항목 ID(D1-05) · verdict_of: 규칙 → 판정 · rules: 검사한 규칙 수(통과 근거)."""
    strong = [s for s in signals if s.score >= min_score]
    if not strong:
        weak = [s.evidence for s in signals]
        return Decision(verdict="allow", confidence=round(1 - max((s.score for s in signals), default=0.0), 3),
                        severity="info", ruleId=f"{item}.pass",
                        evidence=[EvidenceItem(kind="check", note=f"규칙 {rules}종 검사 통과")] + weak)
    top = max(strong, key=lambda s: (VERDICT_RANK[verdict_of[s.rule]], s.score, _SEV[s.severity]))
    verdict = verdict_of[top.rule]
    return Decision(
        verdict=verdict,
        confidence=round(top.score, 3),
        severity=max((s.severity for s in strong), key=_SEV.__getitem__),
        ruleId=f"{item}.{top.rule}",
        evidence=[s.evidence for s in sorted(strong, key=lambda s: -s.score)],
        transform=transform(strong) if verdict == "transform" and transform else None,
    )
