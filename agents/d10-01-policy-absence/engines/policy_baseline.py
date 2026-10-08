"""기본 엔진: 정책을 코드로 선언·버전 관리·차단 베이스라인 배포 여부 (FR-D10-01). artifact = governance_snapshot."""
from aegis.engine import artifact_of, signal

id = "policy_baseline"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a:
        return []
    out = []
    pols = a.get("policies", [])
    if not pols:
        out.append(signal("no-policy", 0.96, "critical", "artifact.policies", "선언형 정책이 하나도 없다"))
    elif not any(p.get("version", 0) >= 1 for p in pols):
        out.append(signal("unversioned", 0.8, "medium", "artifact.policies", "버전 없는 정책"))
    apps = a.get("applications", [])
    if not any(x.get("stage") in ("enforce", "partial") for x in apps):
        out.append(signal("no-enforcement", 0.75, "medium", "artifact.applications",
                          "차단 베이스라인(부분·전체 차단) 적용이 없다 — 관측만 운영 중" if apps else "적용된 프로파일 없음"))
    return out
