"""D10-06 투명성 결여 — 카드 누락·미갱신은 경보."""
from aegis.decide import decide

RULES = {"D10-06.missing-card": "시스템·모델 카드 없음. 경보.", "D10-06.stale-card": "변경 후 카드 미갱신. 경보.",
         "D10-06.pass": "카드 존재·최신성 점검 통과."}


def detect(req, engine):
    return decide("D10-06", engine.scan(req), {"missing-card": "alert", "stale-card": "alert"}, rules=2)
