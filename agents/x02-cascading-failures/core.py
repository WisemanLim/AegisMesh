"""X02 연쇄 실패 — 임계 이상 전파는 차단(전파 경로 차단), 소규모 전파·오류율은 경보."""
from aegis.decide import decide

RULES = {"X02.cascade": "오류 출력이 maxPropagation 개 이상 하위 에이전트로 전파. 전파 차단.",
         "X02.propagation": "오류 출력 전파(임계 미만). 경보.", "X02.error-rate": "에이전트 오류율 임계 초과. 경보.", "X02.pass": "전파 추적 통과."}


def detect(req, engine):
    return decide("X02", engine.scan(req), {"cascade": "block", "propagation": "alert", "error-rate": "alert"}, rules=3)
