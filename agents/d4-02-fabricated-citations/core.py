"""D4-02 인용 날조 — 형식상 불가능한 식별자·미검증 인용을 [인용 미검증] 으로 치환."""
from aegis.decide import decide
from aegis.engine import Signal

RULES = {"D4-02.invalid-id": "형식상 존재할 수 없는 DOI·arXiv 식별자. 제거.",
         "D4-02.unverified": "근거 문서·허용 목록에 없는 인용(URL·DOI·arXiv). [인용 미검증] 으로 치환.",
         "D4-02.pass": "인용 식별자 검사 통과."}


def scrub(output: str, signals: list[Signal]) -> str:
    for s in sorted(signals, key=lambda x: -x.evidence.offset):
        o, n = s.evidence.offset, s.evidence.length
        output = output[:o] + "[인용 미검증]" + output[o + n:]
    return output


def detect(req, engine):
    return decide("D4-02", engine.scan(req), {"invalid-id": "transform", "unverified": "transform"}, rules=2,
                  transform=lambda s: scrub(req.output or "", s))
