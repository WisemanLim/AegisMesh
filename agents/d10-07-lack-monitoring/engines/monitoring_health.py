"""기본 엔진: 상시 관측 — 운영 중인데 관측 없음, 강등·예산 초과 비율 (FR-D10-07)."""
from aegis.engine import artifact_of, signal

id = "monitoring_health"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a or "monitoring" not in a:
        return []
    m = a["monitoring"]
    out = []
    if m.get("activeApplications", 0) > 0 and m.get("gateRecords24h", 0) == 0:
        out.append(signal("blind", 0.9, "high", "artifact.monitoring", "프로파일 적용 중인데 24시간 관문 관측 0건"))
    if m.get("degradedRate", 0) > req.params.get("maxDegradedRate", 0.05):
        out.append(signal("degradation-high", 0.8, "medium", "artifact.monitoring", f"강등 비율 {m['degradedRate']:.1%}"))
    if m.get("overBudgetRate", 0) > req.params.get("maxOverBudgetRate", 0.01):
        out.append(signal("latency-regression", 0.78, "medium", "artifact.monitoring", f"지연 예산 초과 비율 {m['overBudgetRate']:.1%}"))
    if m.get("collector") is False:
        out.append(signal("no-collector", 0.85, "high", "artifact.monitoring", "관측 수집기 미설정"))
    return out
