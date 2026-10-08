"""D5-06 토큰 오용 — 만료·대상·클라이언트·범위 위반은 차단, 과도한 수명은 경보."""
from aegis.decide import decide

KINDS = {"expired": "block", "not-yet-valid": "block", "audience-mismatch": "block", "client-mismatch": "block",
         "scope-insufficient": "block", "long-lived": "alert", "audience-missing": "block"}
RULES = {f"D5-06.{k}": f"토큰 클레임 검사 '{k}' 위반 → {v}." for k, v in KINDS.items()}
RULES["D5-06.pass"] = "토큰 클레임 검사 통과."


def detect(req, engine):
    return decide("D5-06", engine.scan(req), KINDS, rules=len(KINDS))
