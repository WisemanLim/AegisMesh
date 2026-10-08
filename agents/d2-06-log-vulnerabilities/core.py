"""D2-06 로그 취약성 — 로그에 비밀 원문이 이미 있으면 차단(파이프라인 정지 권고), 설정 미흡은 경보."""
from aegis.decide import decide

KINDS = {"secret-in-logs": "block", "no-masking": "alert", "raw-payload": "alert", "retention": "alert", "open-access": "alert"}
RULES = {f"D2-06.{k}": f"관측 파이프라인 점검 '{k}' → {v}." for k, v in KINDS.items()}
RULES["D2-06.pass"] = "관측 파이프라인 마스킹·보존·접근 점검 통과."


def detect(req, engine):
    return decide("D2-06", engine.scan(req), KINDS, rules=len(KINDS))
