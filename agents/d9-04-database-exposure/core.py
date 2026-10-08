"""D9-04 데이터베이스 노출 — 에이전트 계정 과대 권한은 차단, 게이트웨이 미경유·감사 꺼짐은 경보."""
from aegis.decide import decide

VM = {"over-privileged": "block", "direct-access": "alert", "no-audit": "alert"}
RULES = {f"D9-04.{k}": f"DB 계정 점검 '{k}' → {v}." for k, v in VM.items()} | {"D9-04.pass": "에이전트 DB 계정 점검 통과."}


def detect(req, engine):
    return decide("D9-04", engine.scan(req), VM, rules=len(VM))
