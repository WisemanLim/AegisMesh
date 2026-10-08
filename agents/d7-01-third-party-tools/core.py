"""D7-01 서드파티 도구 — 미서명·서명 불일치·미승인·도구 설명 오염·러그풀은 차단(→ 격리 목록), 버전 미고정·과대 권한은 경보."""
from aegis.decide import decide

VM = {"unsigned": "block", "bad-signature": "block", "unapproved": "block", "tool-poisoning": "block", "rug-pull": "block",
      "unpinned": "alert", "broad-permissions": "alert"}
RULES = {f"D7-01.{k}": f"서드파티 MCP 서버·플러그인 심사 '{k}' → {v}." for k, v in VM.items()}
RULES["D7-01.pass"] = "서명·승인·도구 설명·권한 심사 통과."


def detect(req, engine):
    return decide("D7-01", engine.scan(req), VM, rules=len(VM))
