"""기본 엔진: 출력 안 산술 등식·비교 재계산 + 합계 검증 (FR-D4-04 검증자 재실행)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "arithmetic_check"
NUM = r"-?\d+(?:,\d{3})*(?:\.\d+)?"
EQ = re.compile(rf"({NUM})\s*([+\-*/×÷x])\s*({NUM})\s*=\s*({NUM})")
CMP = re.compile(rf"({NUM})\s*(?:is greater than|is larger than|>|보다 크)\s*({NUM})|({NUM})\s*(?:은|는)\s*({NUM})\s*보다\s*크")
PCT = re.compile(rf"({NUM})\s*%")


def f(x: str) -> float:
    return float(x.replace(",", ""))


def scan(req: JudgeRequest) -> list[Signal]:
    text = req.output or ""
    out: list[Signal] = []
    for m in EQ.finditer(text):
        a, op, b, c = f(m.group(1)), m.group(2), f(m.group(3)), f(m.group(4))
        try:
            v = {"+": a + b, "-": a - b, "*": a * b, "×": a * b, "x": a * b, "/": a / b, "÷": a / b}[op]
        except ZeroDivisionError:
            continue
        if abs(v - c) > max(0.01, abs(v) * 0.005):
            out.append(Signal(rule="arithmetic", score=0.92, severity="medium", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note=f"계산 불일치: 재계산 {v:g}")))
    for m in CMP.finditer(text):
        a, b = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        if f(a) <= f(b):
            out.append(Signal(rule="comparison", score=0.88, severity="medium", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note=f"비교 오류: {a} ≤ {b}")))
    samples = [x for x in req.params.get("samples", []) if isinstance(x, str)]
    if len(samples) >= 2 and text:
        mine = sorted(re.findall(NUM, text))
        agree = sum(sorted(re.findall(NUM, x)) == mine for x in samples) / len(samples)
        if agree < 0.5:
            out.append(Signal(rule="inconsistent", score=0.78, severity="medium", evidence=EvidenceItem(
                kind="consistency", location="params.samples", note=f"표본 {len(samples)}개와 수치 일치율 {agree:.0%} — 자기일관성 실패")))
    if req.params.get("percentagesSumTo100"):
        pcts = [f(x) for x in PCT.findall(text)]
        if pcts and abs(sum(pcts) - 100) > 1:
            out.append(Signal(rule="percent-sum", score=0.8, severity="low", evidence=EvidenceItem(
                kind="span", location="output", note=f"구성비 합계 {sum(pcts):g}% ≠ 100%")))
    return out


def explain(req: JudgeRequest) -> dict:
    text = req.output or ""
    eqs = []
    for m in EQ.finditer(text):
        a, op, b, c = f(m.group(1)), m.group(2), f(m.group(3)), f(m.group(4))
        try:
            v = {"+": a + b, "-": a - b, "*": a * b, "×": a * b, "x": a * b, "/": a / b, "÷": a / b}[op]
        except ZeroDivisionError:
            continue
        eqs.append({"expr": m.group(0)[:80], "stated": c, "recomputed": round(v, 6), "ok": abs(v - c) <= max(0.01, abs(v) * 0.005)})
    samples = [x for x in req.params.get("samples", []) if isinstance(x, str)]
    mine = sorted(re.findall(NUM, text))
    cons = [{"sample": i, "numbers": sorted(re.findall(NUM, x))[:8], "agree": sorted(re.findall(NUM, x)) == mine} for i, x in enumerate(samples)]
    return {"kind": "logic", "equations": eqs, "numbers": mine[:12], "samples": cons,
            "agreement": round(sum(c["agree"] for c in cons) / len(cons), 2) if cons else None,
            "note": "검증자 재실행 = 산술 등식·비교 재계산. 자기일관성 = 호출자가 같은 질의 표본 응답(params.samples)을 주면 수치 일치율"}
