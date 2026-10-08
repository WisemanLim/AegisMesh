"""X04 이탈 에이전트 — 미등록·종료된 에이전트는 차단(강제 종료 대상), 하트비트 끊김은 경보 (ASI10)."""
from aegis.decide import decide

RULES = {"X04.unregistered": "레지스트리에 없는 에이전트의 행동. 차단.", "X04.terminated": "종료 처리된 에이전트의 행동. 차단·강제 종료.",
         "X04.stale-heartbeat": "하트비트 끊김. 경보.", "X04.pass": "에이전트 등록·수명 대조 통과."}


def detect(req, engine):
    return decide("X04", engine.scan(req), {"unregistered": "block", "terminated": "block", "stale-heartbeat": "alert"}, rules=3)
