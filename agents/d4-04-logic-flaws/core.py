"""D4-04 논리 오류 — 산술·비교·구성비 합계 재계산 불일치. 경보."""
from aegis.decide import decide

RULES = {"D4-04.arithmetic": "출력의 산술 등식을 재계산하면 값이 다르다. 경보.",
         "D4-04.comparison": "크기 비교 주장이 수치와 모순. 경보.",
         "D4-04.percent-sum": "구성비 합계가 100% 가 아니다(params.percentagesSumTo100). 경보.",
         "D4-04.inconsistent": "같은 질의 표본 응답과 수치가 일치하지 않음(자기일관성 실패). 경보.",
         "D4-04.pass": "산술·비교 재계산 일치."}


def detect(req, engine):
    return decide("D4-04", engine.scan(req), {"arithmetic": "alert", "comparison": "alert", "percent-sum": "alert", "inconsistent": "alert"}, rules=4)
