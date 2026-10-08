"""D3-06 권한 상승 — 범위 초과·자기 권한 상승은 차단, 관리자의 권한 부여는 사람 승인."""
from aegis.decide import decide

RULES = {
    "D3-06.scope-exceeded": "도구 요구 범위가 주체(대리 시 사람∩에이전트) 권한을 넘는다. 차단.",
    "D3-06.self-elevation": "관리자 역할이 없는 주체가 admin·root 권한 부여 도구 호출. 차단.",
    "D3-06.privilege-change": "관리자가 고권한을 부여. 사람 2인 승인.",
    "D3-06.blocked-chain": "정책으로 차단한 도구 연쇄(권한 상승 경로). 차단.",
         "D3-06.pass": "권한 범위 검사 통과.",
}


def detect(req, engine):
    return decide("D3-06", engine.scan(req), {"scope-exceeded": "block", "self-elevation": "block",
                                               "privilege-change": "require_approval", "blocked-chain": "block"}, rules=4)
