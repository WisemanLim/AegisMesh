"""D5-02 인가 파손 — 교차 테넌트·IDOR·필수 역할 누락. 차단 → 403."""
from aegis.decide import decide

RULES = {
    "D5-02.cross-tenant": "주체 테넌트와 자원 테넌트가 다르다. 차단(403).",
    "D5-02.owner-mismatch": "자원 소유자가 아니고 특권 역할도 없다(IDOR). 차단(403).",
    "D5-02.role-missing": "params.requiredRoles 중 어느 역할도 없다. 차단(403).",
    "D5-02.pass": "객체 단위 인가 검사 통과.",
}


def detect(req, engine):
    return decide("D5-02", engine.scan(req), {"cross-tenant": "block", "owner-mismatch": "block", "role-missing": "block"}, rules=3)
