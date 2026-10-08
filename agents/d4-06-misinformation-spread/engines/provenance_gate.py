"""기본 엔진: 전파 전 게이트 — 다른 에이전트·문서·인덱스로 나가는 출력의 출처 표기와 검증 상태 (FR-D4-06).
params.destination: user(기본) | agent | document | index."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "provenance_gate"
CITE = re.compile(r"(https?://\S+|\[\d+\]|\[출처[:：][^\]]+\]|\(source:[^)]+\)|출처\s*[:：])", re.I)
UNVERIFIED = re.compile(r"\[(근거 미확인|인용 미검증)\]")


def scan(req: JudgeRequest) -> list[Signal]:
    dest = req.params.get("destination", "user")
    if dest == "user" or not req.output:
        return []
    out: list[Signal] = []
    cited = bool(CITE.search(req.output)) or bool(req.params.get("provenance"))
    if UNVERIFIED.search(req.output):
        out.append(Signal(rule="unverified-propagation", score=0.9, severity="high", evidence=EvidenceItem(
            kind="span", location="output", note=f"검증 실패 표시가 남은 출력을 {dest} 로 전파")))
    if not cited:
        out.append(Signal(rule="no-provenance", score=0.85 if dest == "index" else 0.7,
                          severity="high" if dest == "index" else "medium",
                          evidence=EvidenceItem(kind="destination", location="params.destination",
                                                note=f"출처 표기 없이 {dest} 로 전파")))
    return out


def explain(req: JudgeRequest) -> dict:
    dest = req.params.get("destination", "user")
    return {"kind": "propagation", "destination": dest, "cited": bool(CITE.search(req.output or "")) or bool(req.params.get("provenance")),
            "unverifiedMarks": len(UNVERIFIED.findall(req.output or "")), "gated": dest != "user"}
