"""D5-04 신원 위장 — SPIFFE 증명 불일치·무서명 에이전트는 차단, 입력 속 권한자 사칭은 경보."""
from aegis.decide import decide

RULES = {
    "D5-04.spiffe-mismatch": "주체가 주장한 SPIFFE ID 와 증명된 SVID 가 다르거나 증명이 없다. 차단.",
    "D5-04.unsigned-agent": "에이전트 주체가 서명·증명 없이 호출. 차단(FR-X01 상호 인증).",
    "D5-04.claimed-authority": "입력 문장에서 관리자·대표 등을 사칭하지만 실제 역할이 없다. 경보(사회공학).",
    "D5-04.pass": "신원 증명 대조 통과.",
}


def detect(req, engine):
    return decide("D5-04", engine.scan(req), {"spiffe-mismatch": "block", "unsigned-agent": "block",
                                               "claimed-authority": "alert"}, rules=3)
