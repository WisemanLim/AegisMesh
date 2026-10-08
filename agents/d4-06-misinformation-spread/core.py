"""D4-06 오정보 확산 — 검증 실패 표시가 남은 출력의 전파·인덱스 적재는 차단, 출처 없는 에이전트·문서 전파는 경보."""
from aegis.decide import decide

RULES = {"D4-06.unverified-propagation": "[근거 미확인]·[인용 미검증] 이 남은 출력을 다른 에이전트·문서·인덱스로 전파. 차단.",
         "D4-06.no-provenance": "출처 표기 없는 전파. 인덱스 적재는 차단, 그 외 경보.",
         "D4-06.pass": "전파 전 출처 게이트 통과(사용자 응답은 대상 아님)."}


def detect(req, engine):
    s = engine.scan(req)
    to_index = req.params.get("destination") == "index"
    return decide("D4-06", s, {"unverified-propagation": "block", "no-provenance": "block" if to_index else "alert"}, rules=2)
