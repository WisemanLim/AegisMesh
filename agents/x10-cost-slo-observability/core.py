"""X10 비용·서비스 수준 관측 — 지연·비용·오탐 예산 초과 경보."""
from aegis.decide import decide

VM = {"latency-budget": "alert", "cost-budget": "alert", "fp-budget": "alert"}
RULES = {f"X10.{k}": f"SLO 점검 '{k}' → 경보." for k in VM} | {"X10.pass": "지연·비용·오탐 예산 이내."}


def detect(req, engine):
    return decide("X10", engine.scan(req), VM, rules=len(VM))
