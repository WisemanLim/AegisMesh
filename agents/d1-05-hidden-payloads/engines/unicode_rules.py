"""기본 엔진: NFKC 정규화 + 비가시 문자·숨김 마크업 탐지 (FR-D1-05)."""
import re
import unicodedata

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "unicode_rules"

TAG = re.compile(r"[\U000E0000-\U000E007F]+")                     # ASCII smuggling (태그 블록)
ZERO_WIDTH = re.compile(r"[​‌‎‏⁠-⁤﻿]")  # ZWJ(U+200D)는 이모지 결합용이라 제외
BIDI = re.compile(r"[‪-‮⁦-⁩]")
INSTR = r"(ignore|disregard|forget|override|instruction|system prompt|you must|you are now|assistant:|무시|지시|시스템 프롬프트|반드시)"
HTML_COMMENT = re.compile(r"<!--(?P<b>.*?)-->", re.S)
HIDDEN_CSS = re.compile(r"<[^>]+style\s*=\s*[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(#fff(fff)?|white))[^\"']*[\"'][^>]*>(?P<b>[^<]{3,})", re.I)
ALT = re.compile(r"\balt\s*=\s*[\"'](?P<b>[^\"']{8,})[\"']", re.I)
INSTR_RE = re.compile(INSTR, re.I)


def _sig(rule, score, sev, kind, loc, m, note):
    return Signal(rule=rule, score=score, severity=sev,
                  evidence=EvidenceItem(kind=kind, location=loc, offset=m.start(), length=m.end() - m.start(), note=note))


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    for loc, text in req.texts("text", "segments"):
        for m in TAG.finditer(text):
            out.append(_sig("unicode-tag", 0.97, "high", "span", loc, m, f"유니코드 태그 블록 {len(m.group())}자 (U+E0000 대역)"))
        zw = list(ZERO_WIDTH.finditer(text))
        if len(zw) >= 2:
            out.append(_sig("zero-width", 0.8, "medium", "span", loc, zw[0], f"제로폭 문자 {len(zw)}개"))
        for m in BIDI.finditer(text):
            out.append(_sig("bidi-override", 0.85, "high", "span", loc, m, f"양방향 제어 문자 U+{ord(m.group()):04X}"))
        for m in HTML_COMMENT.finditer(text):
            if INSTR_RE.search(m.group("b")):
                out.append(_sig("html-comment", 0.9, "high", "span", loc, m, "HTML 주석 안 지시문"))
        for m in HIDDEN_CSS.finditer(text):
            if INSTR_RE.search(m.group("b")):
                out.append(_sig("hidden-css", 0.88, "high", "span", loc, m, f"숨김 스타일({m.group(1)}) 안 지시문"))
        for m in ALT.finditer(text):
            if INSTR_RE.search(m.group("b")):
                out.append(_sig("alt-text", 0.82, "high", "span", loc, m, "이미지 대체텍스트 안 지시문"))
    return out


def explain(req: JudgeRequest) -> dict:
    """NFKC 정규화·비가시 문자 제거 전후 글자 수, 비가시 구간(코드포인트 일부만), 태그 블록 해독 미리보기 (SCR-E02)."""
    rows = []
    for loc, text in req.texts("text", "segments"):
        runs = []
        for kind, rx in (("unicode-tag", TAG), ("zero-width", ZERO_WIDTH), ("bidi", BIDI)):
            for m in rx.finditer(text):
                cps = " ".join(f"U+{ord(c):04X}" for c in m.group()[:3]) + (" …" if len(m.group()) > 3 else "")
                runs.append({"kind": kind, "offset": m.start(), "length": len(m.group()), "codepoints": cps})
        visible = BIDI.sub("", ZERO_WIDTH.sub("", TAG.sub("", text)))
        decoded = "".join(chr(ord(c) - 0xE0000) for r in TAG.findall(text) for c in r if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        rows.append({"location": loc, "chars": len(text), "nfkcChars": len(unicodedata.normalize("NFKC", text)),
                     "visibleChars": len(visible), "invisible": len(text) - len(visible), "runs": runs[:20],
                     "tagDecoded": decoded[:120]})
    return {"kind": "unicode", "rows": rows, "note": "렌더 전/후 글자 수 차이 = 사람이 못 보는 문자. 태그 블록은 ASCII 로 해독해 숨은 지시를 보인다"}
