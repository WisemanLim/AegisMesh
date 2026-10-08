"""D8-04 저장형 프롬프트 공격 — 지시문·실행 표식을 담은 저장 요청 차단(읽기 시점 재검사는 D8-01·D8-03)."""
from aegis.decide import decide

RULES = {"D8-04.directive-stored": "메모리·문서 저장 인자에 모델 대상 지시. 저장 차단.",
         "D8-04.exec-marker": "저장 인자에 템플릿·스크립트 실행 표식. 저장 차단.", "D8-04.pass": "저장 시점 스캔 통과."}


def detect(req, engine):
    return decide("D8-04", engine.scan(req), {"directive-stored": "block", "exec-marker": "block"}, rules=2)
