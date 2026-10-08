"""D4-03 잘못된 결정 — 신뢰도 임계 미만·근거 없는 결정은 사람 승인 경유, 극저신뢰는 차단."""
from aegis.decide import decide

RULES = {"D4-03.low-confidence": "실제 행동으로 이어지는 결정의 신뢰도가 임계 미만. 사람 승인.",
         "D4-03.ungrounded": "근거 인용 없는 결정. 사람 승인.",
         "D4-03.block-low": "결정 신뢰도가 차단 하한(blockBelow) 미만. 차단.",
         "D4-03.pass": "결정 신뢰도 게이트 통과."}


def detect(req, engine):
    return decide("D4-03", engine.scan(req), {"low-confidence": "require_approval", "ungrounded": "require_approval",
                                               "block-low": "block"}, rules=3)
