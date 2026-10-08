"""기본 엔진: 사고 대응 — 열린 고위험 사건의 봉쇄·증거 보존·런북 (FR-X08). artifact.incidents = [{id, severity, ageHours, contained, evidencePreserved, runbook}]"""
from aegis.engine import artifact_of, signal

id = "incident_readiness"


def scan(req):
    a = artifact_of(req, "governance_snapshot", "incident_readiness")
    if not a or "incidents" not in a:
        return []
    out = []
    for inc in a["incidents"]:
        if inc.get("status", "open") != "open" or inc.get("severity") not in ("high", "critical"):
            continue
        loc = f"incident:{inc.get('id')}"
        if not inc.get("evidencePreserved", True):
            out.append(signal("evidence-lost", 0.93, "critical", loc, "사건 재현용 입력·컨텍스트·판정 보존 안 됨"))
        if not inc.get("contained") and inc.get("ageHours", 0) > req.params.get("containWithinHours", 4):
            out.append(signal("uncontained", 0.9, "high", loc, f"{inc['ageHours']}시간째 봉쇄되지 않은 {inc['severity']} 사건"))
        if not inc.get("runbook"):
            out.append(signal("no-runbook", 0.75, "medium", loc, "대응 런북 없음"))
    return out
