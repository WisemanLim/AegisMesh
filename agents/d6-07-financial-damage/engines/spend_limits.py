"""기본 엔진: 지출 상한·승인 임계·되돌릴 수 없는 금전 행동 (FR-D6-07). 금액은 params.currency 기준(기본 KRW)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "spend_limits"
MONEY_TOOL = re.compile(r"(pay|payment|transfer|wire|refund|purchase|buy|order|checkout|withdraw|remit|charge|송금|이체|결제|환불|구매)", re.I)
READ_ONLY = re.compile(r"^(get|list|search|find|read|view|lookup|query|describe|fetch|show|track)[_\-.]|조회", re.I)  # 조회 도구는 금전 행동 아님
AMOUNT_KEYS = ("amount", "total", "price", "value", "sum", "금액")


def amount_of(req: JudgeRequest) -> float | None:
    if req.action and req.action.amount is not None:
        return req.action.amount
    if req.tool:
        for k in AMOUNT_KEYS:
            v = req.tool.args.get(k)
            if isinstance(v, (int, float)):
                return float(v)
    return None


def scan(req: JudgeRequest) -> list[Signal]:
    money = (bool(req.tool and MONEY_TOOL.search(req.tool.name) and not READ_ONLY.search(req.tool.name))
             or bool(req.action and MONEY_TOOL.search(req.action.type)))
    if not money:
        return []
    approved = bool((req.tool and req.tool.approved) or (req.action and req.action.approved))
    amt = amount_of(req)
    p = req.params
    out: list[Signal] = []
    kind = (req.action.type if req.action else None) or (req.tool.name if req.tool else "")
    if p.get("requireCompensation") and kind not in (p.get("compensations") or {}):
        out.append(Signal(rule="no-compensation", score=0.9, severity="high", evidence=EvidenceItem(
            kind="money", location="action.type", note=f"보상 트랜잭션이 등록되지 않은 금전 행동 '{kind}'")))
    if amt is None:
        out.append(Signal(rule="unknown-amount", score=0.8, severity="medium", evidence=EvidenceItem(
            kind="money", location="tool.args", note="금전 행동인데 금액 미상")))
        return out
    if amt > p.get("spendLimit", 10_000_000):
        out.append(Signal(rule="over-limit", score=0.96, severity="critical", evidence=EvidenceItem(
            kind="money", location="amount", note=f"금액 {amt:,.0f} > 지출 상한 {p.get('spendLimit', 10_000_000):,}")))
    elif not approved and amt > p.get("approvalThreshold", 100_000):
        out.append(Signal(rule="needs-approval", score=0.9, severity="high", evidence=EvidenceItem(
            kind="money", location="amount", note=f"금액 {amt:,.0f} > 승인 임계 {p.get('approvalThreshold', 100_000):,} — 2인 승인")))
    if not approved and req.action is not None and not req.action.reversible and amt > 0:
        out.append(Signal(rule="irreversible", score=0.88, severity="high", evidence=EvidenceItem(
            kind="money", location="action.reversible", note="되돌릴 수 없는 금전 행동 — 2인 승인")))
    if p.get("dailySpent") is not None and p["dailySpent"] + amt > p.get("dailyLimit", float("inf")):
        out.append(Signal(rule="daily-limit", score=0.93, severity="high", evidence=EvidenceItem(
            kind="money", location="params.dailySpent", note="일일 지출 한도 초과")))
    return out


def explain(req: JudgeRequest) -> dict:
    p = req.params
    kind = (req.action.type if req.action else None) or (req.tool.name if req.tool else "")
    return {"kind": "spend", "action": kind, "amount": amount_of(req), "spendLimit": p.get("spendLimit", 10_000_000),
            "approvalThreshold": p.get("approvalThreshold", 100_000), "dailySpent": p.get("dailySpent"), "dailyLimit": p.get("dailyLimit"),
            "compensation": (p.get("compensations") or {}).get(kind), "requireCompensation": bool(p.get("requireCompensation")),
            "reversible": req.action.reversible if req.action else None}
