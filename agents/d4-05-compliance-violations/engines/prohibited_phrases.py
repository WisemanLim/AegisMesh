"""기본 엔진: 도메인 금칙 사전 (FR-D4-05) — 금융(자본시장법·금소법 단정적 판단), 의료(의료법 과장 광고), 광고 미고지.
조직 사전은 params.prohibitedPhrases = [{pattern, rule, verdict}] 로 추가."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "prohibited_phrases"

BUILTIN = [
    ("finance-guarantee", "block", 0.92, r"(원금\s*(보장|보전)|확정\s*수익|무위험\s*(수익|투자)|손실\s*(없|0)|guaranteed\s+(returns?|profit)|risk[- ]free\s+(return|investment))"),
    ("finance-advice", "transform", 0.8, r"(지금\s*(당장\s*)?(사|매수|매도)하세요|무조건\s*(오른|상승)|반드시\s*(오른|상승)|you should (buy|sell) now)"),
    ("medical-claim", "block", 0.9, r"(완치\s*(보장|됩니다|가능)|100\s*%\s*(치료|완치|효과)|부작용\s*(이\s*)?(전혀\s*)?없는|cures? (cancer|diabetes) guaranteed)"),
    ("medical-advice", "transform", 0.78, r"(약\s*(복용|투약)을?\s*(중단|끊)하세요|stop taking your (medication|meds))"),
]
AD = re.compile(r"(제휴|협찬|sponsored|affiliate)", re.I)
AD_MARK = re.compile(r"(#광고|\[광고\]|광고\s*포함|#ad\b|\(sponsored\))", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    text = req.output or ""
    out: list[Signal] = []
    rules = BUILTIN + [(p["rule"], p.get("verdict", "transform"), 0.85, p["pattern"]) for p in req.params.get("prohibitedPhrases", [])]
    for rule, _v, score, pat in rules:
        for m in re.finditer(pat, text, re.I):
            out.append(Signal(rule=rule, score=score, severity="high", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note=f"규정 위반 표현({rule})")))
    if (req.params.get("sponsored") or AD.search(text)) and not AD_MARK.search(text):
        out.append(Signal(rule="ad-undisclosed", score=0.8 if req.params.get("sponsored") else 0.6, severity="medium",
                          evidence=EvidenceItem(kind="span", location="output", note="광고·제휴 콘텐츠에 광고 표시 없음")))
    return out


def verdict_map(req: JudgeRequest) -> dict[str, str]:
    m = {r: v for r, v, _s, _p in BUILTIN} | {"ad-undisclosed": "transform"}
    m |= {p["rule"]: p.get("verdict", "transform") for p in req.params.get("prohibitedPhrases", [])}
    return m


def explain(req: JudgeRequest) -> dict:
    """금칙 사전(내장 + 조직)·일치 문구·조치 (SCR-H03)."""
    text = req.output or ""
    org = req.params.get("prohibitedPhrases", [])
    rows = []
    for rule, verdict, _s, pat in BUILTIN + [(p["rule"], p.get("verdict", "transform"), 0.85, p["pattern"]) for p in org]:
        for m in re.finditer(pat, text, re.I):
            rows.append({"phrase": m.group(0)[:60], "rule": rule, "action": "차단" if verdict == "block" else "재작성", "verdict": verdict})
    return {"kind": "compliance", "matches": rows, "dictionary": {"builtin": len(BUILTIN), "org": len(org)},
            "rules": [{"rule": r, "verdict": v, "source": "builtin"} for r, v, _s, _p in BUILTIN] +
                     [{"rule": p["rule"], "verdict": p.get("verdict", "transform"), "source": "org"} for p in org],
            "adUndisclosed": bool((req.params.get("sponsored") or AD.search(text)) and not AD_MARK.search(text))}
