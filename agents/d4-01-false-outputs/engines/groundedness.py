"""기본 엔진: 문장 단위 근거성 — 사실 주장 문장(숫자·날짜·고유명)이 제공 근거 문서로 뒷받침되는지 (FR-D4-01).
근거 문서(retrieval)가 없으면 판정하지 않는다(근거성 판정 불가 ≠ 환각)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "groundedness"
SENT = re.compile(r"(?:[^.!?。\n]|\.(?=\d))+[.!?。]?")          # 소수점(1.2%)은 문장 끝이 아니다
WORD = re.compile(r"\w+", re.U)
CLAIM = re.compile(r"\d|(년|월|일|%|원|달러|억|만)\b|\b[A-Z][a-z]+ [A-Z][a-z]+")
STOP = {"the", "a", "an", "is", "are", "was", "were", "of", "in", "to", "and", "or", "that", "this", "it", "for", "on",
        "은", "는", "이", "가", "을", "를", "의", "에", "로", "으로", "와", "과", "도", "다", "입니다", "있습니다"}


def toks(t: str) -> set[str]:
    return {w.lower() for w in WORD.findall(t) if w.lower() not in STOP}


def scan(req: JudgeRequest) -> list[Signal]:
    docs = [toks(d.text) for d in req.retrieval if d.text]
    if not docs or not req.output:
        return []
    doc_nums = {n.rstrip(".,") for d in req.retrieval for n in re.findall(r"\d[\d,.]*", d.text)}
    out: list[Signal] = []
    for m in SENT.finditer(req.output):
        s = m.group().strip()
        if len(s) < 12 or not CLAIM.search(s):
            continue
        st = toks(s)
        nums = {n.rstrip(".,") for n in re.findall(r"\d[\d,.]*", s)}
        support = max(len(st & d) / len(st) for d in docs) if st else 1.0
        num_ok = nums <= doc_nums                      # 부분 문자열이 아니라 수치 토큰 단위로 대조
        if support < 0.5 or not num_ok:
            out.append(Signal(rule="ungrounded-claim", score=0.85 if not num_ok else 0.7, severity="medium", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(),
                note=f"근거 문서로 뒷받침되지 않는 사실 주장 (어휘 지지율 {support:.2f}{', 수치 불일치' if not num_ok else ''})")))
    return out


def explain(req: JudgeRequest) -> dict:
    """문장 단위 근거성 — 문장별 어휘 지지율·수치 일치·가장 가까운 근거 문서 (SCR-H02)."""
    docs = [(d.id, toks(d.text)) for d in req.retrieval if d.text]
    doc_nums = {n.rstrip(".,") for d in req.retrieval for n in re.findall(r"\d[\d,.]*", d.text)}
    rows = []
    for m in SENT.finditer(req.output or ""):
        s = m.group().strip()
        if len(s) < 6:
            continue
        st = toks(s)
        claim = len(s) >= 12 and bool(CLAIM.search(s))
        scores = [(len(st & d) / len(st) if st else 1.0, i) for i, d in docs]
        best = max(scores, default=(None, None))
        nums = {n.rstrip(".,") for n in re.findall(r"\d[\d,.]*", s)}
        rows.append({"offset": m.start(), "sentence": s[:160], "claim": claim, "support": round(best[0], 2) if best[0] is not None else None,
                     "doc": best[1], "numbersOk": nums <= doc_nums,
                     "grounded": (not claim) or (best[0] is not None and best[0] >= 0.5 and nums <= doc_nums)})
    return {"kind": "grounding", "docs": [i for i, _ in docs], "sentences": rows,
            "note": "사실 주장 문장(숫자·날짜·고유명)만 판정 — 근거 문서가 없으면 판정 불가(환각과 다름)"}
