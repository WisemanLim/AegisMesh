"""D2-02 세션 간 유출 — 다른 테넌트는 차단, 다른 사용자 내용이 출력에 실리면 차단, 그 외 혼입은 경보."""
from aegis.decide import decide

RULES = {
    "D2-02.cross-tenant": "다른 테넌트의 검색 문서·메모리가 컨텍스트에 섞였다. 차단.",
    "D2-02.cross-user": "다른 사용자 소유 항목. 출력에 실렸으면 차단, 컨텍스트에만 있으면 경보.",
    "D2-02.cross-session": "세션 범위 메모리가 다른 세션에서 조회. 경보.",
    "D2-02.pass": "테넌트·사용자·세션 범위 검사 통과.",
}


def detect(req, engine):
    s = engine.scan(req)
    leaked = any(x.rule == "cross-user" and x.score >= 0.9 for x in s)
    return decide("D2-02", s, {"cross-tenant": "block", "cross-user": "block" if leaked else "alert",
                               "cross-session": "alert"}, rules=3)
