"""기본 엔진: 한국어 우선 개인정보·건강정보 사전 + 체크섬 검증 (FR-D2-01). 값은 증거에 남기지 않는다."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "pii_kr"

RRN = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-\s]?([1-8])(\d{6})(?!\d)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
PHONE = re.compile(r"(?<!\d)01[016789][-\s.]?\d{3,4}[-\s.]?\d{4}(?!\d)")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PASSPORT = re.compile(r"\b[MSRODG]\d{8}\b")
HEALTH = re.compile(r"(진단명|병명|확진|투약|처방전|HIV|에이즈|정신과|우울증 진단|암 진단|diagnosed with|prescription for)", re.I)
NAME_CTX = re.compile(r"(환자|고객|성명|이름)\s*[:：]?\s*[가-힣]{2,4}|[가-힣]{2,4}\s*(님|씨|환자)|(patient|customer|name)\s*[:：]\s*[A-Z][a-z]+", re.I)


def rrn_valid(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) != 13:
        return False
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    chk = (11 - sum(int(d) * k for d, k in zip(digits[:12], w)) % 11) % 10
    return chk == int(digits[12]) or digits[6] in "5678"   # 외국인등록번호·2020.10 이후 발급분은 체크섬 미적용


def luhn(num: str) -> bool:
    d = [int(x) for x in num][::-1]
    return sum(x if i % 2 == 0 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(d)) % 10 == 0


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []

    def add(rule, score, sev, loc, m, note):
        out.append(Signal(rule=rule, score=score, severity=sev, evidence=EvidenceItem(
            kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note=note + " (값은 기록하지 않음)")))

    for loc, text in req.texts("output"):
        for m in RRN.finditer(text):
            if rrn_valid(m):
                add("rrn", 0.97, "critical", loc, m, "주민·외국인등록번호")
        for m in CARD.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and luhn(digits) and not RRN.fullmatch(m.group(0).strip()):
                add("card", 0.93, "critical", loc, m, "카드번호(Luhn 통과)")
        for m in PHONE.finditer(text):
            add("phone", 0.8, "medium", loc, m, "휴대전화번호")
        for m in EMAIL.finditer(text):
            if not any(m.group(0).lower().endswith(d) for d in req.params.get("publicEmailDomains", [])):
                add("email", 0.7, "low", loc, m, "이메일 주소")
        for m in PASSPORT.finditer(text):
            add("passport", 0.85, "high", loc, m, "여권번호 형태")
        if (h := HEALTH.search(text)) and NAME_CTX.search(text):
            add("health", 0.82, "high", loc, h, "특정인과 결합된 건강정보")
    return out


def explain(req: JudgeRequest) -> dict:
    """개체 유형별 탐지(위치·길이·가린 미리보기)와 신뢰 구역 노출 모드 (SCR-F02). 값 자체는 돌려주지 않는다."""
    zone = req.params.get("zone")
    zp = (req.params.get("zonePolicy") or {}).get(zone or "")
    if zp is None and zone == "external_model":
        zp = {"*": "block"}
    ents = []
    for s in scan(req):
        e = s.evidence
        ents.append({"type": s.rule, "location": e.location, "offset": e.offset, "length": e.length, "score": s.score,
                     "mode": (zp or {}).get(s.rule, (zp or {}).get("*", "mask" if s.rule != "health" else "alert")) if zone else
                     ("alert" if s.rule == "health" else "mask")})
    return {"kind": "pii", "zone": zone, "zonePolicy": zp, "entities": ents,
            "dictionary": "한국어 개인정보 사전 + 체크섬(주민번호)·Luhn(카드) 검증 — 외부 NER 연동 없음"}
