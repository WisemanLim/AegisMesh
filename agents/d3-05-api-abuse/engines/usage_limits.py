"""기본 엔진: API 사용 한도 — 호출 빈도·대량 파라미터·컬렉션 단위 파괴 메서드 (FR-D3-05).
빈도는 호출자가 집계해 params.recentCalls 로 넘긴다(에이전트는 상태를 갖지 않는다 — 순수 함수)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "usage_limits"

# amount(금액)는 대량 요청이 아니라 D6-07 금전 피해 영역 — 제외
BULK_KEY = re.compile(r"^(limit|count|page_?size|per_?page|max(_?results)?|batch(_?size)?|n|size|quantity)$", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    if t is None:
        return []
    out: list[Signal] = []
    p = req.params
    rl = p.get("rateLimit") or {}
    if rl and p.get("recentCalls") is not None and p["recentCalls"] >= rl.get("calls", 0):
        out.append(Signal(rule="rate-limit", score=0.92, severity="high", evidence=EvidenceItem(
            kind="usage", location="params.recentCalls",
            note=f"{rl.get('windowSec', 60)}초 내 {p['recentCalls']}회 ≥ 한도 {rl['calls']}회")))
    q = (p.get("quotas") or {}).get((req.subject.principal.id if req.subject.principal else None) or "*") or (p.get("quotas") or {}).get("*")
    if q and p.get("usageToday") is not None and q.get("perDay") is not None and p["usageToday"] >= q["perDay"]:
        out.append(Signal(rule="quota-exceeded", score=0.93, severity="high", evidence=EvidenceItem(
            kind="usage", location="params.usageToday", note=f"오늘 {p['usageToday']}회 ≥ 일 쿼터 {q['perDay']}회")))
    if t.approved:          # 사람 승인을 받은 호출은 대량·컬렉션 변경 승인 요구를 다시 내지 않는다(빈도 한도는 유지)
        return out
    max_batch = int(p.get("maxBatch", 1000))
    for k, v in t.args.items():
        if BULK_KEY.match(k) and isinstance(v, (int, float)) and v > max_batch:
            out.append(Signal(rule="bulk-request", score=0.82, severity="medium", evidence=EvidenceItem(
                kind="usage", location=f"args.{k}", note=f"{k}={v} > maxBatch {max_batch}")))
    method = str(t.args.get("method", "")).upper()
    url = str(t.args.get("url") or t.args.get("path") or "")
    if method in ("DELETE", "PUT", "PATCH") and url and not re.search(r"/[\w-]*\d[\w-]*/?(\?.*)?$|/[0-9a-f-]{8,}/?(\?.*)?$", url):
        out.append(Signal(rule="collection-write", score=0.8, severity="high", evidence=EvidenceItem(
            kind="usage", location="args.url", note=f"식별자 없는 컬렉션 경로에 {method}")))
    return out


def explain(req: JudgeRequest) -> dict:
    p = req.params
    pid = req.subject.principal.id if req.subject.principal else None
    q = (p.get("quotas") or {}).get(pid or "*") or (p.get("quotas") or {}).get("*")
    return {"kind": "usage", "principal": pid, "rateLimit": p.get("rateLimit"), "recentCalls": p.get("recentCalls"),
            "quota": q, "usageToday": p.get("usageToday"), "maxBatch": int(p.get("maxBatch", 1000)),
            "note": "빈도·쿼터 집계는 호출자(API 게이트웨이)가 recentCalls·usageToday 로 넘긴다 — 에이전트는 상태를 갖지 않는다"}
