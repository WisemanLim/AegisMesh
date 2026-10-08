"""D5-05 역할 혼동 — 에이전트 특권 역할이 위임자를 넘으면 차단, 위임 증명 없음·역할 변동은 경보."""
from aegis.decide import decide

VM = {"agent-role-exceeds-human": "block", "no-delegation-proof": "alert", "role-drift": "alert"}
RULES = {f"D5-05.{k}": f"역할 혼동 점검 '{k}' → {v}." for k, v in VM.items()} | {"D5-05.pass": "대리 관계·역할 점검 통과."}


def detect(req, engine):
    return decide("D5-05", engine.scan(req), VM, rules=len(VM))
