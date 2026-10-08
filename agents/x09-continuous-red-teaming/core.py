"""X09 상시 레드팀 — 방어 회귀는 배포 게이트 차단, 미등록 대상 실행은 차단, 주기 누락은 경보."""
from aegis.decide import decide

VM = {"regression": "block", "unregistered-target": "block", "stale": "alert"}
RULES = {f"X09.{k}": f"레드팀 점검 '{k}' → {v}." for k, v in VM.items()} | {"X09.pass": "레드팀 회귀·주기 점검 통과."}


def detect(req, engine):
    return decide("X09", engine.scan(req), VM, rules=len(VM))
