"""D8-05 지식 주입 — 미인증 수집·위조 문서는 차단, 미서명 비율·급증은 경보."""
from aegis.decide import decide

VM = {"unauthenticated-ingest": "block", "poisoned-docs": "block", "unsigned-docs": "alert", "ingest-spike": "alert"}
RULES = {f"D8-05.{k}": f"색인 수집 감사 '{k}' → {v}." for k, v in VM.items()} | {"D8-05.pass": "색인 수집 감사 통과."}


def detect(req, engine):
    return decide("D8-05", engine.scan(req), VM, rules=len(VM))
