"""D9-06 네트워크 가로채기 — 외부 평문 흐름·경로 이상은 차단, 이그레스 기본 허용·상호 인증 없음은 경보."""
from aegis.decide import decide

VM = {"plaintext-external": "block", "route-anomaly": "block", "egress-open": "alert", "no-mutual-auth": "alert", "plaintext-internal": "block"}
RULES = {f"D9-06.{k}": f"네트워크 정책 점검 '{k}' → {v}." for k, v in VM.items()} | {"D9-06.pass": "네트워크 정책 점검 통과."}


def detect(req, engine):
    return decide("D9-06", engine.scan(req), VM, rules=len(VM))
