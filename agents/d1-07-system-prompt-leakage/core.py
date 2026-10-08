"""D1-07 시스템 프롬프트 유출 — 판정 로직(순수 함수)."""
from aegis.decide import decide

RULES = {
    "D1-07.canary": "시스템 지시에 심은 카나리 토큰이 출력에 나타남 → 숨은 컨텍스트 추출 확정. 차단.",
    "D1-07.verbatim": "출력이 시스템 지시 문장을 6-gram 기준 15% 이상 재현. 30% 이상이면 차단, 미만이면 경보.",
    "D1-07.secret-in-context": "시스템 지시 안에 자격증명 형태 문자열. 설계 원칙 위반 경보(LLM08: 숨은 컨텍스트는 발견 가능하다고 가정).",
    "D1-07.pass": "3개 규칙 검사 통과.",
}


def detect(req, engine):
    signals = engine.scan(req)
    verdict = {"canary": "block", "secret-in-context": "alert",
               "verbatim": "block" if any(s.rule == "verbatim" and s.severity == "high" for s in signals) else "alert"}
    return decide("D1-07", signals, verdict, rules=3)
