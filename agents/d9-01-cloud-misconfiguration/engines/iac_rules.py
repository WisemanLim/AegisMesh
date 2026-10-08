"""기본 엔진: 클라우드·IaC 정적 검사 (FR-D9-01). artifact = {kind: iac, resources: [{type, name, …}]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "iac_rules"
ADMIN_PORTS = {22, 3389, 5432, 3306, 6379, 27017, 9200, 2375}


def scan(req: JudgeRequest):
    a = artifact_of(req, "iac", "cloud_config")
    if not a:
        return []
    out = []
    for r in a.get("resources", []):
        t, n = r.get("type"), r.get("name", "?")
        loc = f"resource:{t}.{n}"
        if t in ("bucket", "storage") and (r.get("public") or r.get("acl") in ("public-read", "public-read-write")):
            out.append(signal("public-bucket", 0.96, "critical", loc, "공개 버킷"))
        if t in ("bucket", "storage", "db", "disk") and r.get("encrypted") is False:
            out.append(signal("unencrypted", 0.85, "high", loc, "저장 암호화 꺼짐"))
        if t == "iam_policy" and "*" in r.get("actions", []) and "*" in r.get("resources", ["*"]):
            out.append(signal("iam-wildcard", 0.95, "critical", loc, "IAM Action·Resource 모두 '*'"))
        if t == "security_group":
            for rule in r.get("ingress", []):
                if rule.get("cidr") in ("0.0.0.0/0", "::/0") and rule.get("port") in ADMIN_PORTS:
                    out.append(signal("open-admin-port", 0.94, "critical", loc, f"관리 포트 {rule['port']} 전면 개방"))
    return out
