"""D3-01 위험 도구 호출 — 파괴적 SQL 은 차단, 고위험 도구는 사람 승인(approved=true 면 통과)."""
from aegis.decide import decide

RULES = {
    "D3-01.destructive-sql": "도구 인자에 DROP·TRUNCATE 등 스키마 파괴 SQL. 차단.",
    "D3-01.unbounded-write": "WHERE 없는 DELETE·UPDATE. 전체 행 변경 위험 → 차단.",
    "D3-01.high-risk-tool": "삭제·이체·배포 등 되돌리기 어려운 도구. 사람 승인 대기(승인 후 approved=true 로 재호출).",
    "D3-01.dry-run-impact": "드라이런(트랜잭션 롤백 모드) 영향 행 수가 임계 초과이거나 되돌릴 수 없는 변경. 사람 승인.",
         "D3-01.pass": "도구 위험 카탈로그 검사 통과.",
}


def detect(req, engine):
    return decide("D3-01", engine.scan(req), {"destructive-sql": "block", "unbounded-write": "block",
                                               "high-risk-tool": "require_approval", "dry-run-impact": "require_approval"}, rules=4)
