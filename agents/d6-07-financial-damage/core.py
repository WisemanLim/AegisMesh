"""D6-07 금전 피해 — 상한·일일 한도 초과는 차단, 임계 초과·비가역·금액 미상은 2인 승인."""
from aegis.decide import decide

RULES = {"D6-07.over-limit": "지출 상한 초과. 승인으로도 해제 불가 → 차단.", "D6-07.daily-limit": "일일 지출 한도 초과. 차단.",
         "D6-07.needs-approval": "승인 임계 초과 금전 행동. 2인 승인.", "D6-07.irreversible": "되돌릴 수 없는 금전 행동. 2인 승인.",
         "D6-07.unknown-amount": "금전 도구인데 금액을 알 수 없다. 사람 승인.", "D6-07.no-compensation": "보상 트랜잭션이 등록되지 않은 금전 행동(정책 requireCompensation). 차단.",
         "D6-07.pass": "지출 한도 검사 통과."}


def detect(req, engine):
    return decide("D6-07", engine.scan(req), {"over-limit": "block", "daily-limit": "block", "needs-approval": "require_approval",
                                               "irreversible": "require_approval", "unknown-amount": "require_approval", "no-compensation": "block"}, rules=6)
