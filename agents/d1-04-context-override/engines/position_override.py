"""기본 엔진: 긴 컨텍스트 후반의 덮어쓰기 지시 (FR-D1-04) — 위치 편향을 노린 지시는 뒤쪽일수록 위험."""
import re

from aegis.engine import signal
from aegis.schemas import JudgeRequest

id = "position_override"
OVERRIDE = re.compile(r"(\b(the )?(above|previous|earlier|system) (rules|instructions|prompt|policy) (no longer apply|are (void|cancelled|outdated))\b"
                      r"|\bnew system prompt\b|\boverride (the )?(system|safety) (prompt|policy|rules)\b|\bend of system prompt\b"
                      r"|\bignore (the )?system prompt\b|(위|앞|이전)의?\s*(규칙|지시|정책)[은는이가]?\s*(더\s*이상\s*)?(적용되지\s*않|무효)|새로운\s*시스템\s*프롬프트)", re.I)


def scan(req: JudgeRequest):
    parts = [("text", req.text or "")] + [(f"segments[{i}]", s.text) for i, s in enumerate(req.segments)]
    total = sum(len(t) for _, t in parts)
    if not total:
        return []
    out, pos = [], 0
    long_ctx = total >= req.params.get("longContextChars", 4000)
    for loc, t in parts:
        for m in OVERRIDE.finditer(t):
            rel = (pos + m.start()) / total
            late = long_ctx and rel >= req.params.get("lateFraction", 0.7)
            out.append(signal("late-override" if late else "override", 0.93 if late else 0.72, "high" if late else "medium", loc,
                              f"정책 덮어쓰기 지시 (컨텍스트 {rel:.0%} 위치{', 긴 컨텍스트 후반' if late else ''})", "span", m.start(), m.end() - m.start()))
        pos += len(t)
    return out


def explain(req: JudgeRequest) -> dict:
    """위치별 덮어쓰기 지시 — 컨텍스트 안 상대 위치와 긴 컨텍스트 후반 여부 (SCR-E02)."""
    parts = [("text", req.text or "")] + [(f"segments[{i}]", s.text) for i, s in enumerate(req.segments)]
    total = sum(len(t) for _, t in parts)
    lc, lf = req.params.get("longContextChars", 4000), req.params.get("lateFraction", 0.7)
    hits, pos = [], 0
    for loc, t in parts:
        for m in OVERRIDE.finditer(t):
            rel = (pos + m.start()) / total if total else 0
            hits.append({"location": loc, "position": round(rel, 3), "late": total >= lc and rel >= lf})
        pos += len(t)
    return {"kind": "position", "totalChars": total, "longContext": total >= lc, "longContextChars": lc, "lateFraction": lf,
            "hits": hits, "note": "후반 지시는 위치 편향을 노린다 — 시스템 지시 재삽입(샌드위치)은 런타임 조립 단계의 대응"}
