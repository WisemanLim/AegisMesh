"""X07 모델·추론 계층 — 공개 무인증·취약 버전·산출물 불일치는 차단, 추출 패턴은 경보."""
from aegis.decide import decide

VM = {"open-endpoint": "block", "vulnerable-server": "block", "artifact-mismatch": "block", "extraction-pattern": "alert"}
RULES = {f"X07.{k}": f"추론 계층 점검 '{k}' → {v}." for k, v in VM.items()} | {"X07.pass": "추론 계층 점검 통과."}


def detect(req, engine):
    return decide("X07", engine.scan(req), VM, rules=len(VM))
