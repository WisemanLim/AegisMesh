"""D8-07 검색 편향 — 한 출처가 과대 대표되면 경보."""
from aegis.decide import decide

RULES = {"D8-07.source-dominance": "검색 결과의 한 출처 비중이 maxSourceShare 초과. 경보.", "D8-07.pass": "출처 분포 점검 통과."}


def detect(req, engine):
    return decide("D8-07", engine.scan(req), {"source-dominance": "alert"}, rules=1)
