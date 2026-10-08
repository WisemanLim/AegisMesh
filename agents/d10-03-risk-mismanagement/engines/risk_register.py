"""기본 엔진: 위험 등록부 — 수용 결정의 책임자·기한, 기한 초과 (FR-D10-03)."""
import time

from aegis.engine import artifact_of, signal

id = "risk_register"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a or "riskRegister" not in a:
        return []
    now = req.params.get("now", time.time())
    reg = a["riskRegister"]
    out = []
    if not reg:
        out.append(signal("empty-register", 0.7, "low", "artifact.riskRegister", "위험 등록부가 비어 있다"))
    for r in reg:
        loc = f"risk:{r.get('id')}"
        if r.get("decision") == "accept" and (not r.get("owner") or not r.get("dueAt")):
            out.append(signal("accept-without-owner", 0.85, "medium", loc, "수용 결정에 책임자·기한 없음"))
        if r.get("dueAt") is not None and r["dueAt"] < now and r.get("status", "open") == "open":
            out.append(signal("overdue", 0.8, "medium", loc, "처리 기한 초과"))
        if r.get("score") is None:
            out.append(signal("unscored", 0.72, "low", loc, "점수 체계(AIVSS) 미적용"))
    return out
