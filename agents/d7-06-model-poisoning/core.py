"""D7-06 모델 오염 — 위험 역직렬화·불안전 형식·해시·서명 불일치는 차단(→ 격리), 서명 없음은 경보."""
from aegis.decide import decide

VM = {"dangerous-deserialization": "block", "unsafe-format": "block", "hash-mismatch": "block", "bad-signature": "block", "unsigned": "alert"}
RULES = {f"D7-06.{k}": f"모델 산출물 점검 '{k}' → {v}." for k, v in VM.items()} | {"D7-06.pass": "모델 형식·해시·서명 점검 통과."}


def detect(req, engine):
    return decide("D7-06", engine.scan(req), VM, rules=len(VM))
