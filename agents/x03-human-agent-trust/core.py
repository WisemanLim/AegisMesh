"""X03 사람-에이전트 신뢰 악용 — 자격증명 요구는 차단, 승인 반복·압박 문구는 경보."""
from aegis.decide import decide

VM = {"credential-request": "block", "approval-fatigue": "alert", "pressure": "alert"}
RULES = {f"X03.{k}": f"상호작용 점검 '{k}' → {v}." for k, v in VM.items()} | {"X03.pass": "사람-에이전트 상호작용 점검 통과."}


def detect(req, engine):
    return decide("X03", engine.scan(req), VM, rules=len(VM))
