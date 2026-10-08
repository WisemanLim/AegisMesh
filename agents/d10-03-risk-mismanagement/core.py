"""D10-03 위험관리 부실 — 위험 등록부 미흡은 경보."""
from aegis.decide import decide

VM = {"empty-register": "alert", "accept-without-owner": "alert", "overdue": "alert", "unscored": "alert"}
RULES = {f"D10-03.{k}": f"위험 등록부 점검 '{k}' → 경보." for k in VM} | {"D10-03.pass": "위험 등록부 점검 통과."}


def detect(req, engine):
    return decide("D10-03", engine.scan(req), VM, rules=len(VM))
