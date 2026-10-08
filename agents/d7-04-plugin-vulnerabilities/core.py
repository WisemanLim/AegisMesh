"""D7-04 플러그인 취약 — 권한 미선언·선언 밖 권한·프롬프트 표면 주입은 차단, 샌드박스 없음은 경보."""
from aegis.decide import decide

VM = {"undeclared-permissions": "block", "permission-creep": "block", "prompt-surface-injection": "block", "no-sandbox": "alert"}
RULES = {f"D7-04.{k}": f"플러그인 점검 '{k}' → {v}." for k, v in VM.items()} | {"D7-04.pass": "플러그인 권한·표면 점검 통과."}


def detect(req, engine):
    return decide("D7-04", engine.scan(req), VM, rules=len(VM))
