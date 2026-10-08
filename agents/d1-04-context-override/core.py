"""D1-04 컨텍스트 덮어쓰기 — 긴 컨텍스트 후반의 덮어쓰기 지시는 차단(시스템 지시 재삽입 권고), 그 외 위치는 경보."""
from aegis.decide import decide

RULES = {"D1-04.late-override": "긴 컨텍스트 후반부에 시스템 정책 덮어쓰기 지시(위치 편향 공격). 차단.",
         "D1-04.override": "정책 덮어쓰기 지시. 경보.", "D1-04.pass": "위치별 덮어쓰기 지시 미검출."}


def detect(req, engine):
    return decide("D1-04", engine.scan(req), {"late-override": "block", "override": "alert"}, rules=2)
