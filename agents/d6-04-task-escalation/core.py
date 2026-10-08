"""D6-04 과업 확대 — 범위 밖 도구·자원은 차단, 범위 밖 행동·계획 확장은 승인 사건으로."""
from aegis.decide import decide

RULES = {"D6-04.tool-out-of-scope": "과업 범위 계약 밖 도구. 차단.", "D6-04.resource-out-of-scope": "범위 밖 자원 접근. 차단.",
         "D6-04.action-out-of-scope": "범위 밖 행동. 사람 승인(범위 변경 사건).", "D6-04.plan-expansion": "계획에 범위 밖 하위 과업 추가. 사람 승인.",
         "D6-04.pass": "과업 범위 계약 안."}


def detect(req, engine):
    return decide("D6-04", engine.scan(req), {"tool-out-of-scope": "block", "resource-out-of-scope": "block",
                                               "action-out-of-scope": "require_approval", "plan-expansion": "require_approval"}, rules=4)
