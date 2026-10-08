"""기본 엔진: 에이전트 DB 계정 권한 (FR-D9-04). artifact = {kind: db_accounts, accounts: [{user, usedBy, privileges, viaGateway, queryAudit}]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "db_accounts"
OVER = {"ALL", "ALL PRIVILEGES", "SUPERUSER", "DROP", "ALTER", "GRANT", "CREATE ROLE", "DBA", "OWNER", "DDL"}   # DDL = 스키마 변경 권한


def scan(req: JudgeRequest):
    a = artifact_of(req, "db_accounts")
    if not a:
        return []
    out = []
    for acc in a.get("accounts", []):
        if acc.get("usedBy") != "agent":
            continue
        loc = f"account:{acc.get('user')}"
        priv = {p.upper() for p in acc.get("privileges", [])}
        if priv & OVER:
            out.append(signal("over-privileged", 0.94, "critical", loc, f"에이전트 DB 계정 과대 권한 {sorted(priv & OVER)}"))
        if not acc.get("viaGateway", False):
            out.append(signal("direct-access", 0.78, "medium", loc, "DB 접근 게이트웨이 미경유"))
        if not acc.get("queryAudit", False):
            out.append(signal("no-audit", 0.72, "medium", loc, "쿼리 감사 꺼짐"))
    return out
