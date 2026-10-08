"""X06 멀티모달 공격면 — 첨부 텍스트·메타데이터·숨김 층의 지시문은 차단, 추출 불가 첨부는 경보."""
from aegis.decide import decide

VM = {"embedded-instruction": "block", "metadata-instruction": "block", "hidden-layer": "block", "unscanned": "alert"}
RULES = {f"X06.{k}": f"멀티모달 첨부 검사 '{k}' → {v}." for k, v in VM.items()} | {"X06.pass": "첨부 인젝션 검사 통과."}


def detect(req, engine):
    return decide("X06", engine.scan(req), VM, rules=len(VM))
