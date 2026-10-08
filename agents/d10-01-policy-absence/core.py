"""D10-01 정책 부재 — 정책 없음은 차단(배포 게이트), 버전 없음·차단 베이스라인 없음은 경보."""
from aegis.decide import decide

VM = {"no-policy": "block", "unversioned": "alert", "no-enforcement": "alert"}
RULES = {f"D10-01.{k}": f"정책 베이스라인 점검 '{k}' → {v}." for k, v in VM.items()} | {"D10-01.pass": "정책 선언·버전·차단 베이스라인 확인."}


def detect(req, engine):
    return decide("D10-01", engine.scan(req), VM, rules=len(VM))
