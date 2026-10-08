"""D2-07 메모리 잔존 — 삭제 후 사본 잔존은 차단(삭제 재전파 필요), TTL 초과·증적 미발행은 경보."""
from aegis.decide import decide

RULES = {"D2-07.residual-copy": "삭제 요청 이후 원본·인덱스·캐시·백업에 사본 잔존. 차단(재전파). 백업 유예 기간 내는 낮은 신뢰도.",
         "D2-07.no-receipt": "삭제 증적 미발행. 경보.",
         "D2-07.ttl-expired": "메모리 항목 TTL 초과 잔존. 경보.",
         "D2-07.pass": "삭제 전파·TTL 점검 통과."}


def detect(req, engine):
    return decide("D2-07", engine.scan(req), {"residual-copy": "block", "no-receipt": "alert", "ttl-expired": "alert"}, rules=3)
