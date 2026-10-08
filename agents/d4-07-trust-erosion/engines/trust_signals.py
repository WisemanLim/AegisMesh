"""기본 엔진: 신뢰 신호 — 저신뢰 응답의 불확실성 미표기 + 피드백 지표 회귀 (FR-D4-07).
params.modelConfidence(응답 신뢰도), artifact.kind=feedback_stats {negativeRate, baselineNegativeRate, window}."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "trust_signals"
HEDGE = re.compile(r"(확실하지 않|정확하지 않을 수|추정|가능성이|불확실|may be|might|not sure|uncertain|approximately|추정됩니다|확인이 필요)", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    conf = req.params.get("modelConfidence")
    if conf is not None and conf < req.params.get("lowConfidence", 0.5) and req.output and not HEDGE.search(req.output):
        out.append(Signal(rule="overconfident", score=0.75, severity="low", evidence=EvidenceItem(
            kind="output", location="output", note=f"응답 신뢰도 {conf} 인데 불확실성 표기 없음")))
    a = req.artifact or {}
    if a.get("kind") == "feedback_stats":
        neg, base = a.get("negativeRate", 0), a.get("baselineNegativeRate", 0)
        if neg - base > req.params.get("trustRegression", 0.05):
            out.append(Signal(rule="trust-regression", score=0.85, severity="medium", evidence=EvidenceItem(
                kind="metric", location="artifact.negativeRate", note=f"부정 피드백 {neg:.2%} (기준 {base:.2%}) — 신뢰 회귀")))
    return out
