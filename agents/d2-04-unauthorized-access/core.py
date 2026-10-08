"""D2-04 무단 접근 — 권한 없는 문서가 컨텍스트에 들어오면 차단(검색 프리필터 실패)."""
from aegis.decide import decide

RULES = {"D2-04.acl-denied": "검색 결과에 요청 주체가 열람할 수 없는 문서(ACL)가 포함. 차단 후 재검색.",
         "D2-04.pass": "검색 결과 ACL 재검증 통과."}


def detect(req, engine):
    return decide("D2-04", engine.scan(req), {"acl-denied": "block"}, rules=1)
