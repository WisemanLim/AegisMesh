"""D9-07 서비스 거부 — 단일 출처 집중 폭주는 차단(평판 기반 차단), 급증·레이트리밋 없음·확장 상한 없음은 경보."""
from aegis.decide import decide

VM = {"flood": "block", "surge": "alert", "no-rate-limit": "alert", "unbounded-scale": "alert"}
RULES = {f"D9-07.{k}": f"트래픽 점검 '{k}' → {v}." for k, v in VM.items()} | {"D9-07.pass": "트래픽 점검 통과."}


def detect(req, engine):
    return decide("D9-07", engine.scan(req), VM, rules=len(VM))
