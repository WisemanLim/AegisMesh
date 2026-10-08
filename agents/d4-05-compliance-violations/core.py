"""D4-05 규정 위반 출력 — 단정적 투자 권유·의료 과장은 차단, 그 외 금칙은 표현 삭제(재작성), 광고 미고지는 표시 추가."""

from aegis.decide import decide
from aegis.engine import Signal

RULES = {"D4-05.finance-guarantee": "원금 보장·확정 수익 등 단정적 판단 제공(금소법·자본시장법). 차단.",
         "D4-05.finance-advice": "즉시 매수·매도 권유. 해당 표현 삭제.",
         "D4-05.medical-claim": "완치 보장·부작용 없음 등 의료 과장(의료법). 차단.",
         "D4-05.medical-advice": "복약 중단 권고. 해당 표현 삭제.",
         "D4-05.ad-undisclosed": "광고·제휴 콘텐츠 표시 누락(표시광고법). [광고] 표시 추가.",
         "D4-05.pass": "도메인 금칙 사전 통과."}


def rewrite(output: str, signals: list[Signal]) -> str:
    for s in sorted([x for x in signals if x.evidence.offset is not None], key=lambda x: -x.evidence.offset):
        o, n = s.evidence.offset, s.evidence.length
        output = output[:o] + "[규정 위반 표현 삭제]" + output[o + n:]
    if any(s.rule == "ad-undisclosed" for s in signals):
        output = "[광고] " + output
    return output


def detect(req, engine):
    vm = engine.module.verdict_map(req) if hasattr(engine, "module") else {}
    return decide("D4-05", engine.scan(req), vm, rules=len(vm), transform=lambda s: rewrite(req.output or "", s))
