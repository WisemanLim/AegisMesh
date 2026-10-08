"""D4-07 신뢰 침식 — 저신뢰 응답에 불확실성 문구 추가(무해화), 피드백 지표 회귀는 경보."""
from aegis.decide import decide

RULES = {"D4-07.overconfident": "응답 신뢰도가 낮은데 불확실성 표기가 없다. 안내 문구 추가.",
         "D4-07.trust-regression": "부정 피드백 비율이 기준 대비 회귀. 경보.",
         "D4-07.pass": "신뢰 신호 검사 통과."}
NOTE = "\n\n※ 이 답변은 정확하지 않을 수 있습니다. 중요한 결정 전에 확인해 주세요."


def detect(req, engine):
    return decide("D4-07", engine.scan(req), {"overconfident": "transform", "trust-regression": "alert"}, rules=2,
                  transform=lambda _s: (req.output or "") + NOTE)
