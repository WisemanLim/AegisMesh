"""D3-07 무단 실행 — 허용목록 밖 도구는 차단, 승인 없는 코드 실행은 사람 승인."""
from aegis.decide import decide

RULES = {
    "D3-07.not-allowlisted": "params.toolAllowlist 에 없는 도구. 차단.",
    "D3-07.code-exec": "코드·셸 실행 도구를 승인 없이 호출. 사람 승인(실행은 L2 이상 샌드박스).",
    "D3-07.pass": "도구 허용목록·실행 승인 검사 통과.",
}


def detect(req, engine):
    return decide("D3-07", engine.scan(req), {"not-allowlisted": "block", "code-exec": "require_approval"}, rules=2)
