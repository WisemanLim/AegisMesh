"""기본 엔진: 탈옥 코퍼스 패턴 + leetspeak 정규화 + base64 은닉 + 적대 접미사 휴리스틱 (FR-D1-03)."""
import base64
import binascii
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "jailbreak_corpus"

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
CORPUS = [
    ("dan", 0.96, r"\b(do anything now|dan mode|you are dan|jailbroken|jailbreak mode)\b"),
    ("dev-mode", 0.94, r"\b(developer|god|sudo|unrestricted) mode (is )?(now )?(enabled|activated)\b|\byou are (now )?in (developer|god|sudo|unrestricted) mode\b"),
    ("no-rules", 0.9, r"\b(without|ignore|bypass|disable|remove)\b.{0,15}\b(any|your|all)\b.{0,10}\b(restrictions?|filters?|guidelines|safety|censorship|content polic(y|ies)|ethic(s|al guidelines))\b"),
    ("persona", 0.88, r"\b(you are|act as|pretend to be|roleplay as)\b.{0,20}\b(evil|unfiltered|uncensored|amoral|unrestricted)\b"),
    ("fiction-wrapper", 0.82, r"\b(hypothetical(ly)?|for a (story|novel|movie)|in a fictional world)\b.{0,80}\b(how to (make|build|synthesi[sz]e|cook)|step[- ]by[- ]step)\b.{0,40}\b(bomb|explosive|meth|weapon|malware|ransomware|nerve agent)\b"),
    ("ko-jailbreak", 0.9, r"(탈옥|제한\s*(이\s*)?(없는|없이|을\s*해제)|필터\s*없이|검열\s*(없는|없이)|윤리\s*(규칙|지침)[을를]?\s*(무시|해제)|안전\s*(정책|규칙)[을를]?\s*(무시|우회))"),
    # 직접 지시 덮어쓰기·프롬프트 추출 (사용자 입력 자체 — 간접 주입은 D1-01)
    ("override", 0.88, r"\b(ignore|disregard|forget|override)\b.{0,20}\b(previous|prior|above|earlier|preceding|system|original)\b.{0,15}\b(instructions?|prompts?|rules|directions|directives)\b"),
    ("ko-override", 0.88, r"(이전|앞선|위의|기존|원래|시스템)\s*(의\s*)?(모든\s*)?(지시|명령|지침|프롬프트|규칙)\S{0,3}\s*(은|는|을|를)?\s*(모두|전부|다)?\s*(무시|잊어|따르지\s*마)"),
    ("prompt-extraction", 0.86, r"\b(reveal|print|show|repeat|output|dump|leak)\b.{0,20}\b(your|the)\s+(system prompt|hidden (instructions|prompt)|initial (prompt|instructions))\b"
                                 r"|시스템\s*프롬프트[를을]?\s*(그대로\s*|전부\s*)?(출력|보여|알려|공개)"),
]
RX = [(r, s, re.compile(p, re.I | re.S)) for r, s, p in CORPUS]
B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
ODD = re.compile(r"\\|\*\*|\]\(|!--|[a-z]{3,}[A-Z]")


def _adversarial(text: str) -> re.Match | None:
    """GCG 계열 적대 접미사: 역슬래시·'**'·'](' ·'!--'·단어 붙여쓰기(similarlyNow) 같은 이상 토큰이 3개 이상 몰린 구간."""
    toks = list(re.finditer(r"\S+", text))
    for i in range(len(toks)):
        win = toks[i:i + 10]
        if sum(bool(ODD.search(t.group())) for t in win) >= 3:
            return _span(text, win[0].start(), win[-1].end())
    return None


def _span(text: str, a: int, b: int) -> re.Match:
    return re.compile(r"[\s\S]{%d}" % (b - a)).match(text, a)


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    for loc, text in req.texts("text", "segments"):
        norm = text.translate(LEET)
        for rule, score, rx in RX:
            if (m := rx.search(norm)):
                out.append(Signal(rule=rule, score=score, severity="high", evidence=EvidenceItem(
                    kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note=f"탈옥 코퍼스 유형 {rule}")))
        for m in B64.finditer(text):
            try:
                dec = base64.b64decode(m.group(), validate=True).decode("utf-8", "strict")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if any(rx.search(dec) for _, _, rx in RX) or re.search(r"ignore|instruction|system prompt", dec, re.I):
                out.append(Signal(rule="encoded", score=0.88, severity="high", evidence=EvidenceItem(
                    kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="base64 인코딩 안에 탈옥·지시문")))
        if (m := _adversarial(text)):
            out.append(Signal(rule="adversarial-suffix", score=0.72, severity="medium", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="적대 접미사 형태(구두점 밀도 높음)")))
    return out


def explain(req: JudgeRequest) -> dict:
    """코퍼스 유형별 일치(유사도 = 유형 점수)·인코딩 다단계·적대 접미사와 합성 (SCR-E03)."""
    matches = []
    for loc, text in req.texts("text", "segments"):
        norm = text.translate(LEET)
        for rule, score, rx in RX:
            if rx.search(norm):
                matches.append({"family": rule, "score": score, "location": loc, "leet": norm != text and not rx.search(text)})
        for m in B64.finditer(text):
            try:
                dec = base64.b64decode(m.group(), validate=True).decode("utf-8", "strict")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            hit = [r for r, _, rx in RX if rx.search(dec)]
            if hit or re.search(r"ignore|instruction|system prompt", dec, re.I):
                matches.append({"family": "encoded:" + (hit[0] if hit else "directive"), "score": 0.88, "location": loc, "leet": False})
        if _adversarial(text):
            matches.append({"family": "adversarial-suffix", "score": 0.72, "location": loc, "leet": False})
    matches.sort(key=lambda m: -m["score"])
    return {"kind": "jailbreak", "matches": matches[:20], "top": matches[0]["score"] if matches else 0.0,
            "corpus": len(CORPUS), "note": "유형 점수 = 코퍼스 패턴 신뢰도. 합성 판정은 가장 높은 신호 + 정책 임계"}
