"""기본 엔진: 결정 신뢰도 게이트 — 결제·배포·통지 등 실제 행동의 결정 신뢰도·근거 확보 여부 (FR-D4-03)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "decision_gate"
CONSEQUENTIAL = ("payment", "pay", "transfer", "refund", "order", "deploy", "notify", "notification", "approve", "loan",
                 "send_email", "publish", "delete", "결제", "송금", "배포", "통지", "승인")


READ_ONLY = ("get", "lookup", "list", "read", "search", "fetch", "view", "find", "조회", "검색")


def scan(req: JudgeRequest) -> list[Signal]:
    a = req.action
    if a is None or a.approved:
        return []
    words = [w for w in re.split(r"[_\-\s.]+", a.type.lower()) if w]
    read_only = bool(words) and words[0] in READ_ONLY and a.impact in ("low", "medium") and a.reversible
    consequential = any(k in words or (not k.isascii() and k in a.type) for k in CONSEQUENTIAL)
    if read_only or not (consequential or a.impact in ("high", "critical") or not a.reversible):
        return []
    by = req.params.get("thresholdsByAction") or {}
    key = next((k for k in by if k in words or (not k.isascii() and k in a.type)), None)
    th = float(by[key] if key else req.params.get("decisionThreshold", 0.75))
    out: list[Signal] = []
    if a.confidence is not None and a.confidence < th:
        low = a.confidence < float(req.params.get("blockBelow", 0.3))
        out.append(Signal(rule="block-low" if low else "low-confidence", score=0.9 if low else 0.85, severity="high",
                          evidence=EvidenceItem(kind="decision", location="action.confidence",
                                                note=f"결정 신뢰도 {a.confidence} < 임계 {th} ({a.type})")))
    if a.grounded is False:
        out.append(Signal(rule="ungrounded", score=0.82, severity="high", evidence=EvidenceItem(
            kind="decision", location="action.grounded", note=f"근거 인용 없이 내린 결정 ({a.type})")))
    return out


def explain(req: JudgeRequest) -> dict:
    a = req.action
    by = req.params.get("thresholdsByAction") or {}
    if a is None:
        return {"kind": "decision", "action": None, "thresholds": by, "default": req.params.get("decisionThreshold", 0.75)}
    words = [w for w in re.split(r"[_\-\s.]+", a.type.lower()) if w]
    key = next((k for k in by if k in words or (not k.isascii() and k in a.type)), None)
    th = float(by[key] if key else req.params.get("decisionThreshold", 0.75))
    return {"kind": "decision", "action": a.type, "impact": a.impact, "reversible": a.reversible, "confidence": a.confidence,
            "grounded": a.grounded, "matched": key, "threshold": th, "blockBelow": float(req.params.get("blockBelow", 0.3)),
            "thresholds": by, "default": req.params.get("decisionThreshold", 0.75),
            "result": "approved" if a.approved else "block" if a.confidence is not None and a.confidence < float(req.params.get("blockBelow", 0.3))
            else "require_approval" if a.confidence is not None and a.confidence < th else "pass"}
