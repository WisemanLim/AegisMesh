"""D8-02 장기 조작 — 승인 정책 위반 쓰기는 차단, 장기 행동 유도 문구·쓰기 급증은 경보."""
from aegis.decide import decide

VM = {"unapproved-write": "block", "persistent-directive": "alert", "write-burst": "alert"}
RULES = {f"D8-02.{k}": f"메모리 장기 조작 점검 '{k}' → {v}." for k, v in VM.items()} | {"D8-02.pass": "메모리 쓰기·변동 점검 통과."}


def detect(req, engine):
    return decide("D8-02", engine.scan(req), VM, rules=len(VM))
