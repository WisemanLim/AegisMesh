"""기본 엔진: 방어 자체의 지연·비용·오탐 예산 (FR-X10). artifact.slo = {gates: {g: {p95, budget}}, costUsd, budgetUsd, fpRate, fpBudget}"""
from aegis.engine import artifact_of, signal

id = "slo_budget"


def scan(req):
    a = artifact_of(req, "governance_snapshot", "slo_stats")
    slo = (a or {}).get("slo") if a and a.get("kind") == "governance_snapshot" else a
    if not slo:
        return []
    out = []
    for g, v in (slo.get("gates") or {}).items():
        if v.get("budget") and v.get("p95", 0) > v["budget"]:
            out.append(signal("latency-budget", 0.85, "medium", f"slo.gates.{g}", f"{g} 관문 p95 {v['p95']}ms > 예산 {v['budget']}ms"))
    if slo.get("budgetUsd") and slo.get("costUsd", 0) > slo["budgetUsd"]:
        out.append(signal("cost-budget", 0.8, "medium", "slo.costUsd", f"방어 비용 ${slo['costUsd']} > 예산 ${slo['budgetUsd']}"))
    if slo.get("fpBudget") is not None and slo.get("fpRate", 0) > slo["fpBudget"] * req.params.get("warnAt", 0.8):
        out.append(signal("fp-budget", 0.82, "medium", "slo.fpRate", f"오탐률 {slo['fpRate']:.3%} — 오탐 예산 {slo['fpBudget']:.3%} 의 80% 초과(NFR-Q6)"))
    return out
