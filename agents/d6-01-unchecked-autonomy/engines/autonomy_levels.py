"""기본 엔진: 행동 영향 등급 대 자율 레벨 (FR-D6-01). params.autonomyLevel: 0(모두 승인)~3(critical 외 자율)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "autonomy_levels"
IMPACT = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def scan(req: JudgeRequest) -> list[Signal]:
    a = req.action
    if a is None or a.approved or (req.tool and req.tool.approved):
        return []
    level = int(req.params.get("autonomyLevel", 1))
    need = IMPACT[a.impact] + (1 if a.external else 0) + (1 if not a.reversible else 0)
    if need > level:
        return [Signal(rule="over-autonomy", score=min(0.95, 0.75 + 0.05 * (need - level)), severity="high", evidence=EvidenceItem(
            kind="action", location="action.impact",
            note=f"행동 등급 {need}(impact {a.impact}{', 외부' if a.external else ''}{', 비가역' if not a.reversible else ''}) > 자율 레벨 {level}"))]
    return []


def explain(req: JudgeRequest) -> dict:
    a = req.action
    level = int(req.params.get("autonomyLevel", 1))
    need = (IMPACT[a.impact] + (1 if a.external else 0) + (1 if not a.reversible else 0)) if a else None
    return {"kind": "autonomy", "level": level, "action": a.type if a else None, "impact": a.impact if a else None,
            "external": a.external if a else None, "reversible": a.reversible if a else None, "need": need,
            "result": None if a is None else "approved" if a.approved else "require_approval" if need > level else "auto",
            "table": [{"grade": f"I{g}", "auto": g <= level} for g in range(0, 6)],
            "note": "행동 등급 = impact(low 0·medium 1·high 2·critical 3) + 외부 1 + 비가역 1 — 자율 레벨 초과는 사람 승인"}
