"""D6-03 무한 루프 — 동일 호출 반복·진전 없음은 차단, 상태 왕복·장시간 실행은 경보."""
from aegis.decide import decide

RULES = {"D6-03.repeat-call": "같은 도구·인자 호출이 maxRepeat 회 연속. 차단.", "D6-03.no-progress": "상태 해시가 maxNoProgress 단계 동안 불변. 차단.",
         "D6-03.cycle": "상태 2개 사이 왕복. 경보.", "D6-03.timeout": "실행 시간 상한 초과. 경보(내구 실행 재개 권고).",
         "D6-03.pass": "반복·진전 검사 통과."}


def detect(req, engine):
    return decide("D6-03", engine.scan(req), {"repeat-call": "block", "no-progress": "block", "cycle": "alert", "timeout": "alert"}, rules=4)
