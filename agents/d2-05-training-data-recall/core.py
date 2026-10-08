"""D2-05 학습 데이터 재현 — 카나리는 차단, 장문 재현은 경보. 근본 대응(차등 프라이버시)은 학습 단계 통제(R09)."""
from aegis.decide import decide

RULES = {"D2-05.canary": "학습 데이터에 심은 카나리 문자열이 출력에 재현. 차단.",
         "D2-05.verbatim": "보호 코퍼스 8-gram 3개 이상 재현. 경보.",
         "D2-05.pass": "카나리·장문 재현 검사 통과."}


def detect(req, engine):
    return decide("D2-05", engine.scan(req), {"canary": "block", "verbatim": "alert"}, rules=2)
