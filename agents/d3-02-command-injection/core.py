"""D3-02 명령 주입 — 도구 인자의 셸·SQL 주입. 차단."""
from aegis.decide import decide

RULES = {
    "D3-02.shell-meta": "셸 실행 도구 인자에 ; && || | 백틱 $( ) 등 메타문자 — 추가 명령 연결. 차단.",
    "D3-02.substitution": "일반 인자에 명령 치환 구문(백틱·$()). 차단.",
    "D3-02.sql-injection": "질의 인자에 항진식·UNION SELECT·스택 질의. 차단.",
    "D3-02.pass": "셸·SQL 주입 패턴 미검출.",
}


def detect(req, engine):
    return decide("D3-02", engine.scan(req), {"shell-meta": "block", "substitution": "block", "sql-injection": "block"}, rules=3)
