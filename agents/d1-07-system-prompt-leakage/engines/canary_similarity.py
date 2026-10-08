"""기본 엔진: 카나리 토큰 대조 + 시스템 지시 문장 재현(n-gram) + 숨은 컨텍스트 비밀 검사 (FR-D1-07, LLM08)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "canary_similarity"

CANARY = re.compile(r"AEGIS-CANARY-[A-Z0-9]{8,}")
SECRET = re.compile(r"(sk-[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                    r"(password|passwd|비밀번호)\s*[:=]\s*\S{6,}|postgres(ql)?://[^\s:]+:[^\s@]+@)", re.I)
WORD = re.compile(r"\w+", re.U)
N = 6


def _shingles(text: str) -> set[tuple[str, ...]]:
    w = [x.lower() for x in WORD.findall(text)]
    return {tuple(w[i:i + N]) for i in range(len(w) - N + 1)}


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    system, output = req.system or "", req.output or ""
    canaries = set(CANARY.findall(system)) | set(req.params.get("canaries", []))
    for c in canaries if req.params.get("matchOutput", True) else ():
        if (pos := output.find(c)) >= 0:
            out.append(Signal(rule="canary", score=0.99, severity="critical", evidence=EvidenceItem(
                kind="span", location="output", offset=pos, length=len(c), note="시스템 지시의 카나리 토큰이 출력에 나타남")))
    sys_sh = _shingles(system)
    if sys_sh and output:
        ratio = len(sys_sh & _shingles(output)) / len(sys_sh)
        if ratio >= req.params.get("similarityThreshold", 0.15):
            out.append(Signal(rule="verbatim", score=min(0.99, 0.5 + ratio), severity="high" if ratio >= 0.3 else "medium",
                              evidence=EvidenceItem(kind="similarity", location="output",
                                                    note=f"시스템 지시 {N}-gram 재현율 {ratio:.2f}")))
    if (m := SECRET.search(system)):
        out.append(Signal(rule="secret-in-context", score=0.9, severity="high", evidence=EvidenceItem(
            kind="span", location="system", offset=m.start(), length=m.end() - m.start(),
            note="숨은 컨텍스트에 자격증명 형태 문자열 — 비밀은 컨텍스트에 두지 않는다(LLM08)")))
    return out


def explain(req: JudgeRequest) -> dict:
    """카나리 대조·시스템 지시 n-gram 재현율 대 임계·숨은 컨텍스트 비밀 형태 (SCR-E04). 토큰·비밀 값은 앞뒤 일부만."""
    system, output = req.system or "", req.output or ""
    canaries = sorted(set(CANARY.findall(system)) | set(req.params.get("canaries", [])))
    mask = lambda c: f"{c[:6]}…{c[-2:]}" if len(c) > 10 else "●" * len(c)   # noqa: E731
    sys_sh = _shingles(system)
    ratio = len(sys_sh & _shingles(output)) / len(sys_sh) if sys_sh and output else 0.0
    return {"kind": "leak", "canaries": [{"token": mask(c), "inOutput": c in output} for c in canaries],
            "matchOutput": req.params.get("matchOutput", True), "ngram": N, "ratio": round(ratio, 3),
            "threshold": req.params.get("similarityThreshold", 0.15), "secretInSystem": bool(SECRET.search(system))}
