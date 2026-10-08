"""D10-02 규제 위반 — 보존 기간 미달·국외 이전 위반은 차단, 매핑 누락 통제는 경보. 법률 판단이 아니다(PRD 부록 E)."""
from aegis.decide import decide

VM = {"retention-short": "block", "egress-violation": "block", "unmapped-controls": "alert"}
RULES = {f"D10-02.{k}": f"규제 통제 매핑 점검 '{k}' → {v}." for k, v in VM.items()} | {"D10-02.pass": "통제 매핑·보존·이전 정책 점검 통과."}


def detect(req, engine):
    return decide("D10-02", engine.scan(req), VM, rules=len(VM))
