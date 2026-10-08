"""D8-06 메모리 손상 — 체크섬 불일치는 차단(복구 지점으로 되돌림), 충돌 중복은 경보(충돌 해소 규칙)."""
from aegis.decide import decide

RULES = {"D8-06.checksum-mismatch": "메모리 레코드 체크섬 불일치. 차단 후 복구 지점 사용.",
         "D8-06.conflict": "같은 ID 의 상충 레코드. 경보.", "D8-06.pass": "메모리 무결성 점검 통과."}


def detect(req, engine):
    return decide("D8-06", engine.scan(req), {"checksum-mismatch": "block", "conflict": "alert"}, rules=2)
