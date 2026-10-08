"""D6-01 통제 없는 자율성 — 행동 등급이 자율 레벨을 넘으면 사람 승인."""
from aegis.decide import decide

RULES = {"D6-01.over-autonomy": "행동 영향 등급(impact + 외부 영향 + 비가역)이 에이전트 자율 레벨을 넘는다. 사람 승인.",
         "D6-01.pass": "자율 레벨 안의 행동."}


def detect(req, engine):
    return decide("D6-01", engine.scan(req), {"over-autonomy": "require_approval"}, rules=1)
