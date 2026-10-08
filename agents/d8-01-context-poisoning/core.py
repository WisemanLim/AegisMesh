"""D8-01 컨텍스트 오염 — 신뢰 안 되는 출처 문서의 지시문은 차단(문서 제외 후 재조립), 신뢰 출처·미서명은 경보."""
from aegis.decide import decide

RULES = {"D8-01.poisoned-doc": "검색 문서·도구 응답에 모델 대상 지시. untrusted 출처는 차단, trusted 는 경보.",
         "D8-01.unsigned-doc": "requireSignedDocs 정책에서 서명 없는 문서. 경보.", "D8-01.pass": "컨텍스트 조각 인젝션 스캔 통과."}


def detect(req, engine):
    s = engine.scan(req)
    hard = any(x.rule == "poisoned-doc" and x.score >= 0.9 for x in s)
    return decide("D8-01", s, {"poisoned-doc": "block" if hard else "alert", "unsigned-doc": "alert"}, rules=2)
