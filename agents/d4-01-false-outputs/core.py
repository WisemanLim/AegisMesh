"""D4-01 허위 출력 — 근거 미확보 문장에 [근거 미확인] 표시(무해화). regulated-kr 은 정책으로 동일 transform."""
from aegis.decide import decide
from aegis.engine import Signal

RULES = {"D4-01.ungrounded-claim": "근거 문서로 뒷받침되지 않는 숫자·날짜·고유명 주장. 해당 문장에 [근거 미확인] 표시.",
         "D4-01.pass": "문장 단위 근거성 검사 통과(또는 근거 문서 없음)."}


def mark(output: str, signals: list[Signal]) -> str:
    for s in sorted(signals, key=lambda x: -x.evidence.offset):
        end = s.evidence.offset + s.evidence.length
        output = output[:end] + " [근거 미확인]" + output[end:]
    return output


def detect(req, engine):
    return decide("D4-01", engine.scan(req), {"ungrounded-claim": "transform"}, rules=1,
                  transform=lambda s: mark(req.output or "", s))
