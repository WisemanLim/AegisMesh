"""X05 출력 처리 부실 — HTML 싱크는 이스케이프(무해화), SQL·셸 싱크의 위험 구문은 차단 (LLM10)."""
import html

from aegis.decide import decide

RULES = {
    "X05.xss": "HTML·마크다운 렌더 대상 출력에 스크립트·이벤트 핸들러·javascript: URL. HTML 이스케이프 후 통과.",
    "X05.sql-sink": "SQL 로 실행될 출력에 다중 문장·파괴 구문. 차단.",
    "X05.shell-sink": "셸로 실행될 출력에 명령 연결·치환·파괴 구문. 차단.",
    "X05.pass": "하위 시스템별 출력 검사 통과.",
}


def detect(req, engine):
    return decide("X05", engine.scan(req), {"xss": "transform", "sql-sink": "block", "shell-sink": "block"}, rules=3,
                  transform=lambda _s: html.escape(req.output or "", quote=True))
