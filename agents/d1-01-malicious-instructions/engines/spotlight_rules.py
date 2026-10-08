"""기본 엔진: 신뢰할 수 없는 출처(웹·문서·메일·도구 응답) 안의 모델 대상 지시문 탐지 (FR-D1-01, 간접 인젝션)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "spotlight_rules"

DIRECTIVES = [
    ("override", 0.92, r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,20}\b(instructions?|rules|prompts?|directions)\b"),
    ("override", 0.92, r"(이전|위의|앞의|기존)\s*(지시|명령|규칙|지침)[을를은는]?\s*(모두\s*)?(무시|잊어)"),
    ("persona", 0.85, r"\b(you are now|from now on,? you|act as (an?|the) (system|admin|developer))\b"),
    ("persona", 0.85, r"(지금부터|이제부터)\s*(너는|당신은)"),
    ("covert", 0.9, r"\b(do not|don't|never)\s+(tell|inform|mention|reveal)\b.{0,20}\b(the )?(user|human|anyone)\b"),
    ("covert", 0.9, r"사용자에게\s*(알리지|말하지|보여주지)\s*(말고|마)"),
    ("action", 0.88, r"\b(instead|now|immediately)\b.{0,20}\b(send|email|forward|upload|post|transfer|wire)\b.{0,40}\b(to|at)\b"),
    ("action", 0.88, r"(대신|즉시|지금)\s*.{0,20}(전송|송금|보내|업로드|전달)"),
    ("role-marker", 0.88, r"(<\|im_start\|>|<\|system\|>|\[\[?SYSTEM\]?\]|^\s*(system|assistant)\s*:|</?(system|instructions?)>)"),
    ("new-instructions", 0.86, r"\b(new|updated|additional) (instructions|task|objective)\s*:"),
]
RX = [(r, s, re.compile(p, re.I | re.M)) for r, s, p in DIRECTIVES]


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    for i, seg in enumerate(req.segments):
        if seg.trust != "untrusted":
            continue
        for rule, score, rx in RX:
            if (m := rx.search(seg.text)):
                out.append(Signal(rule=rule, score=score, severity="high", evidence=EvidenceItem(
                    kind="span", location=f"segments[{i}]", offset=m.start(), length=m.end() - m.start(),
                    note=f"신뢰할 수 없는 출처({seg.source})에 모델 대상 지시({rule})")))
    return out


def explain(req: JudgeRequest) -> dict:
    """세그먼트별 출처 신뢰·지시 권한·스포트라이팅 경계와 걸린 지시 유형 (SCR-E02)."""
    segs = []
    for i, seg in enumerate(req.segments):
        hits = sorted({rule for rule, _, rx in RX if seg.trust == "untrusted" and rx.search(seg.text)})
        segs.append({"i": i, "source": seg.source, "trust": seg.trust, "chars": len(seg.text),
                     "authority": "데이터 전용 «»" if seg.trust == "untrusted" else "지시 권한", "hits": hits})
    return {"kind": "segments", "segments": segs,
            "note": "신뢰할 수 없는 출처는 데이터로만 감싸고(«» 스포트라이팅) 그 안의 모델 대상 지시를 찾는다"}
