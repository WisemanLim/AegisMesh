"""D7-07 API 침해 — 허용목록 밖·지문 불일치·응답 조작은 차단(→ 격리), 증명 없음은 경보."""
from aegis.decide import decide

VM = {"egress-denied": "block", "pin-mismatch": "block", "response-tampered": "block", "no-attestation": "alert"}
RULES = {f"D7-07.{k}": f"상위 API 무결성 '{k}' → {v}." for k, v in VM.items()} | {"D7-07.pass": "공급자 무결성 점검 통과."}


def detect(req, engine):
    return decide("D7-07", engine.scan(req), VM, rules=len(VM))
