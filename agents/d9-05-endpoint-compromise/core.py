"""D9-05 엔드포인트 침해 — 평문 자격증명·무결성 실패는 차단, EDR·세션·하드웨어 키는 경보."""
from aegis.decide import decide

VM = {"plaintext-credentials": "block", "integrity-fail": "block", "no-edr": "alert", "long-session": "alert", "no-hw-key": "alert"}
RULES = {f"D9-05.{k}": f"엔드포인트 점검 '{k}' → {v}." for k, v in VM.items()} | {"D9-05.pass": "엔드포인트 상태 점검 통과."}


def detect(req, engine):
    return decide("D9-05", engine.scan(req), VM, rules=len(VM))
