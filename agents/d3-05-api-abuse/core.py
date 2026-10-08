"""D3-05 API 남용 — 호출 한도 초과는 차단, 대량·컬렉션 단위 변경은 사람 승인."""
from aegis.decide import decide

RULES = {
    "D3-05.rate-limit": "시간 창 안 호출 수가 한도 이상(params.rateLimit). 차단.",
    "D3-05.bulk-request": "limit·count 등 대량 파라미터가 maxBatch 초과. 사람 승인.",
    "D3-05.collection-write": "식별자 없는 컬렉션 경로에 DELETE·PUT·PATCH. 사람 승인.",
    "D3-05.quota-exceeded": "주체 일 쿼터 소진(호출자 집계 usageToday). 차단.",
         "D3-05.pass": "API 사용 한도 검사 통과.",
}


def detect(req, engine):
    return decide("D3-05", engine.scan(req), {"rate-limit": "block", "bulk-request": "require_approval",
                                               "collection-write": "require_approval", "quota-exceeded": "block"}, rules=4)
