"""D2-03 자격증명 유출 — 판정 로직(순수 함수). 출력의 자격증명을 마스킹(transform)한다."""
from aegis.decide import decide
from aegis.engine import Signal

KINDS = ["anthropic-key", "openai-key", "aws-access-key", "github-token", "slack-token",
         "google-api-key", "private-key", "jwt", "conn-string"]
RULES = {f"D2-03.{k}": f"{k} 형태 자격증명이 출력·입력에 포함. 출력은 [REDACTED_…] 로 마스킹, 입력 측은 경보." for k in KINDS}
RULES["D2-03.pass"] = f"{len(KINDS)}개 자격증명 패턴 검사 통과."


def mask(output: str, signals: list[Signal]) -> str:
    spans = sorted(((s.evidence.offset, s.evidence.length, s.rule) for s in signals
                    if s.evidence.location == "output"), reverse=True)
    for off, ln, rule in spans:
        output = output[:off] + f"[REDACTED_{rule.upper().replace('-', '_')}]" + output[off + ln:]
    return output


def detect(req, engine):
    signals = engine.scan(req)
    in_output = any(s.evidence.location == "output" for s in signals)
    verdict = {k: ("transform" if in_output else "alert") for k in KINDS}
    return decide("D2-03", signals, verdict, rules=len(KINDS), transform=lambda s: mask(req.output or "", s))
