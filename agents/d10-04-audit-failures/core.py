"""D10-04 감사 실패 — 원장 무결성 실패는 차단(사건), 체크포인트 지연·익명 행동은 경보."""
from aegis.decide import decide

VM = {"ledger-broken": "block", "stale-checkpoint": "alert", "anonymous-actions": "alert"}
RULES = {f"D10-04.{k}": f"감사 추적 점검 '{k}' → {v}." for k, v in VM.items()} | {"D10-04.pass": "원장 무결성·감사 주체 점검 통과."}


def detect(req, engine):
    return decide("D10-04", engine.scan(req), VM, rules=len(VM))
