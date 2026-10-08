"""기본 엔진: 상시 레드팀 — 회귀(탐지율 < 기준선)·주기 미실행·미등록 대상 (FR-X09).
artifact.redteam = {lastRunAgeSec, results: [{agent, detectionRate, baseline}], unregisteredTargets: [...]}"""
from aegis.engine import artifact_of, signal

id = "redteam_regression"


def scan(req):
    a = artifact_of(req, "governance_snapshot", "redteam_status")
    rt = (a or {}).get("redteam") if a and a.get("kind") == "governance_snapshot" else a
    if not rt:
        return []
    out = []
    reg = [r for r in rt.get("results", []) if r.get("detectionRate", 1) < r.get("baseline", 0)]
    if reg:
        out.append(signal("regression", 0.95, "high", "redteam.results",
                          f"방어 회귀 {len(reg)}종: " + ", ".join(f"{r['agent']} {r['detectionRate']:.2f}<{r['baseline']:.2f}" for r in reg[:4])))
    if rt.get("lastRunAgeSec") is None or rt["lastRunAgeSec"] > req.params.get("maxAgeSec", 7 * 86400):
        out.append(signal("stale", 0.75, "medium", "redteam.lastRunAgeSec", "레드팀 주기 실행 누락"))
    if rt.get("unregisteredTargets"):
        out.append(signal("unregistered-target", 0.95, "critical", "redteam.unregisteredTargets", "사전 등록되지 않은 레드팀 대상(이중 용도 통제 §13.1)"))
    return out
