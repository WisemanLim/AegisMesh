"""D7-03 라이브러리 백도어 — 설치 시 원격 실행·난독화·타이포스쿼팅은 차단(→ 격리), 신규·저신뢰는 경보."""
from aegis.decide import decide

VM = {"install-remote-exec": "block", "obfuscation": "block", "typosquat": "block", "low-trust": "alert"}
RULES = {f"D7-03.{k}": f"패키지 휴리스틱 '{k}' → {v}." for k, v in VM.items()} | {"D7-03.pass": "패키지 휴리스틱 통과."}


def detect(req, engine):
    return decide("D7-03", engine.scan(req), VM, rules=len(VM))
