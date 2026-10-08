"""기본 엔진: 도구 위험 카탈로그 — 파괴적·고위험 도구와 위험 SQL (FR-D3-01)."""
import re

from aegis.engine import Signal, walk_strings
from aegis.schemas import EvidenceItem, JudgeRequest

id = "risk_catalog"

HIGH_RISK = re.compile(r"^(delete|drop|destroy|purge|wipe|truncate|rm|terminate|shutdown|reboot|transfer|wire|pay|refund|"
                       r"send_(bulk|mass)|bulk_|mass_|deploy|rollback|revoke|reset)[_\-a-z]*$|.*_(delete|destroy|purge|wipe|all)$", re.I)
SQL_DESTRUCTIVE = re.compile(r"\b(drop\s+(table|database|schema)|truncate\s+table|alter\s+table\s+\w+\s+drop)\b", re.I)
SQL_UNBOUNDED = re.compile(r"\b(delete\s+from|update)\s+\w+(\s+set\s+[^;]+?)?\s*(;|$)(?![\s\S]*\bwhere\b)", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    if t is None:
        return []
    out: list[Signal] = []
    extra = {x.lower() for x in req.params.get("highRiskTools", [])}
    for loc, v in walk_strings(t.args):
        if (m := SQL_DESTRUCTIVE.search(v)):
            out.append(Signal(rule="destructive-sql", score=0.95, severity="critical", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="스키마 파괴 SQL(DROP·TRUNCATE)")))
        elif "where" not in v.lower() and (m := SQL_UNBOUNDED.search(v)):
            out.append(Signal(rule="unbounded-write", score=0.9, severity="high", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="WHERE 없는 전체 DELETE·UPDATE")))
    dry = req.params.get("dryRun")                        # 호출자 드라이런(트랜잭션 롤백 모드) 결과 {tables, rows, reversible}
    if isinstance(dry, dict) and not t.approved:
        limit = int(req.params.get("maxRowsWithoutApproval", 1000))
        rows = int(dry.get("rows") or 0)
        if rows > limit:
            out.append(Signal(rule="dry-run-impact", score=0.9, severity="high", evidence=EvidenceItem(
                kind="dryrun", location="params.dryRun.rows", note=f"드라이런 영향 {rows:,}행 > 임계 {limit:,}행 ({rows / max(limit, 1):.1f}배)")))
        elif dry.get("reversible") is False and rows > 0:
            out.append(Signal(rule="dry-run-impact", score=0.86, severity="high", evidence=EvidenceItem(
                kind="dryrun", location="params.dryRun.reversible", note=f"되돌릴 수 없는 변경 {rows:,}행")))
    if (HIGH_RISK.match(t.name) or t.name.lower() in extra) and not t.approved:
        out.append(Signal(rule="high-risk-tool", score=0.85, severity="high", evidence=EvidenceItem(
            kind="tool", location="tool.name", note=f"고위험 도구 '{t.name}' — 되돌리기 어려운 행동")))
    return out


def explain(req: JudgeRequest) -> dict:
    """인자별 SQL 위험·도구 위험 등급·드라이런 영향 대 임계 (SCR-G02)."""
    t = req.tool
    if t is None:
        return {"kind": "toolcall", "tool": None}
    args = []
    for loc, v in walk_strings(t.args):
        args.append({"arg": loc, "chars": len(v), "destructiveSql": bool(SQL_DESTRUCTIVE.search(v)),
                     "unboundedWrite": "where" not in v.lower() and bool(SQL_UNBOUNDED.search(v))})
    dry = req.params.get("dryRun") if isinstance(req.params.get("dryRun"), dict) else None
    limit = int(req.params.get("maxRowsWithoutApproval", 1000))
    return {"kind": "toolcall", "tool": t.name, "approved": t.approved,
            "highRisk": bool(HIGH_RISK.match(t.name)) or t.name.lower() in {x.lower() for x in req.params.get("highRiskTools", [])},
            "args": args, "dryRun": dry, "rowLimit": limit,
            "ratio": round((dry.get("rows") or 0) / max(limit, 1), 2) if dry else None,
            "note": "드라이런은 호출자가 트랜잭션 롤백 모드로 실행해 params.dryRun 으로 넘긴다 — 임계 초과는 사람 승인, 파괴적 SQL 은 차단"}
