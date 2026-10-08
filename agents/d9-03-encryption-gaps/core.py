"""D9-03 암호화 공백 — 평문·만료 인증서·미암호화 저장은 차단, mTLS 미적용·만료 임박·약한 TLS 는 경보."""
from aegis.decide import decide

VM = {"plaintext": "block", "cert-expired": "block", "unencrypted-store": "block", "no-mtls": "alert", "cert-expiring": "alert", "weak-tls": "alert"}
RULES = {f"D9-03.{k}": f"암호화 점검 '{k}' → {v}." for k, v in VM.items()} | {"D9-03.pass": "암호화 인벤토리 점검 통과."}


def detect(req, engine):
    return decide("D9-03", engine.scan(req), VM, rules=len(VM))
