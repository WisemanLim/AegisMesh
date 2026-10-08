"""D6-05 목표 불일치 — 검증 무력화·기댓값 하드코딩·지표 조작은 차단, 미해결 종결·경보 억제는 경보."""
from aegis.decide import decide

VM = {"disable-checks": "block", "hardcode-expected": "block", "tamper-metric": "block",
      "close-without-fix": "alert", "suppress-signal": "alert", "custom": "block"}
RULES = {f"D6-05.{k}": f"금지 수단 '{k}' — 지표는 만족시키되 의도를 벗어남. {v}." for k, v in VM.items()}
RULES["D6-05.pass"] = "금지 수단 검사 통과."


def detect(req, engine):
    s = engine.scan(req)
    vm = VM | {x.rule: "block" for x in s if x.rule not in VM}
    return decide("D6-05", s, vm, rules=len(VM))
