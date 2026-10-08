"""기본 엔진: 규제 통제 ↔ 시스템 통제 매핑과 증적 수집 (FR-D10-02). artifact = governance_snapshot.controls / retention."""
from aegis.engine import artifact_of, signal

id = "control_mapping"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a:
        return []
    out = []
    for fw, c in (a.get("controls") or {}).items():
        if c.get("missing"):
            out.append(signal("unmapped-controls", 0.8, "medium", f"artifact.controls.{fw}",
                              f"{fw} 통제 {len(c['missing'])}개가 시스템 통제·증적에 매핑되지 않음: {c['missing'][:4]}"))
    r = a.get("retention") or {}
    if r.get("requiredDays") and r.get("configuredDays", 0) < r["requiredDays"]:
        out.append(signal("retention-short", 0.92, "high", "artifact.retention",
                          f"증적 보존 {r.get('configuredDays')}일 < 규제 프로파일 요구 {r['requiredDays']}일"))
    if a.get("modelEgress") == "allow" and a.get("regionPolicy") == "deny":
        out.append(signal("egress-violation", 0.93, "high", "artifact.modelEgress", "국외 이전 금지 프로파일인데 외부 모델 호출 허용(NFR-D5)"))
    return out
