"""X01 에이전트 간 통신 보안 — 서명 없음·미신뢰 키·서명 불일치·지문 불일치·평문 통신은 차단 (ASI07)."""
from aegis.decide import decide

KINDS = ["unsigned-card", "untrusted-key", "bad-signature", "pin-mismatch", "plaintext"]
RULES = {f"X01.{k}": f"에이전트 간 통신 신뢰 검사 '{k}' 실패. 차단." for k in KINDS}
RULES["X01.pass"] = "AgentCard 서명·인증서 고정·TLS 검사 통과."


def detect(req, engine):
    return decide("X01", engine.scan(req), {k: "block" for k in KINDS}, rules=len(KINDS))
