"""D6-06 자원 고갈 — 쿼터 초과는 차단(강등 실행), 근접·과대 호출은 경보."""
from aegis.decide import decide

RULES = {"D6-06.quota-exceeded": "주체 쿼터(토큰·시간·동시성·저장소·비용) 초과. 차단.", "D6-06.quota-near": "쿼터 90% 이상. 경보(백프레셔).",
         "D6-06.oversized-call": "호출당 토큰 상한 초과 요청. 경보.", "D6-06.pass": "쿼터 검사 통과."}


def detect(req, engine):
    return decide("D6-06", engine.scan(req), {"quota-exceeded": "block", "quota-near": "alert", "oversized-call": "alert"}, rules=3)
