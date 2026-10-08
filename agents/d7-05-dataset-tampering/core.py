"""D7-05 데이터셋 변조 — 승인 없는 해시 변경은 차단, 분포 이동·급증은 경보."""
from aegis.decide import decide

VM = {"unapproved-change": "block", "label-shift": "alert", "row-spike": "alert"}
RULES = {f"D7-05.{k}": f"데이터셋 무결성 '{k}' → {v}." for k, v in VM.items()} | {"D7-05.pass": "데이터셋 해시·분포 점검 통과."}


def detect(req, engine):
    return decide("D7-05", engine.scan(req), VM, rules=len(VM))
