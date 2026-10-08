"""D1-02 지시 탈취 — 목표 불변식 대조. 목표 재정의는 차단, 목표 밖 고위험 단계는 사람 승인."""
from aegis.decide import decide

RULES = {
    "D1-02.goal-override": "입력·계획에 원래 목표를 덮어쓰거나 폐기하라는 지시. 차단.",
    "D1-02.plan-drift": "계획 단계에 원래 목표에 없는 고위험 행동(전송·이체·삭제 등)이 추가됨. 사람 승인 대기.",
    "D1-02.pass": "목표 불변식 유지.",
}


def detect(req, engine):
    return decide("D1-02", engine.scan(req), {"goal-override": "block", "plan-drift": "require_approval"}, rules=2)
