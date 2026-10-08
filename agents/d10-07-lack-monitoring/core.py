"""D10-07 모니터링 부재 — 운영 중 관측 0건은 차단, 강등·지연 회귀·수집기 없음은 경보."""
from aegis.decide import decide

VM = {"blind": "block", "degradation-high": "alert", "latency-regression": "alert", "no-collector": "alert"}
RULES = {f"D10-07.{k}": f"상시 관측 점검 '{k}' → {v}." for k, v in VM.items()} | {"D10-07.pass": "상시 관측 점검 통과."}


def detect(req, engine):
    return decide("D10-07", engine.scan(req), VM, rules=len(VM))
