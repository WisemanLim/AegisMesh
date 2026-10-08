"""X08 사고 대응·포렌식 — 증거 미보존·장시간 미봉쇄는 차단(에스컬레이션), 런북 없음은 경보."""
from aegis.decide import decide

VM = {"evidence-lost": "block", "uncontained": "block", "no-runbook": "alert"}
RULES = {f"X08.{k}": f"사고 대응 점검 '{k}' → {v}." for k, v in VM.items()} | {"X08.pass": "열린 사건 대응 상태 점검 통과."}


def detect(req, engine):
    return decide("X08", engine.scan(req), VM, rules=len(VM))
