"""기본 엔진: 상태 해시 반복·동일 호출 반복·진전 없음 (FR-D6-03). history 항목 {tool, args, stateHash}."""
import json

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "loop_detector"


def key(tool, args) -> str:
    return f"{tool}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"


def scan(req: JudgeRequest) -> list[Signal]:
    hist = req.history
    p = req.params
    out: list[Signal] = []
    calls = [key(h.get("tool"), h.get("args", {})) for h in hist if h.get("tool")]
    if req.tool:
        calls.append(key(req.tool.name, req.tool.args))
    run = 1
    for i in range(len(calls) - 1, 0, -1):
        if calls[i] == calls[i - 1]:
            run += 1
        else:
            break
    if run >= int(p.get("maxRepeat", 3)):
        out.append(Signal(rule="repeat-call", score=0.93, severity="high", evidence=EvidenceItem(
            kind="history", location="history", note=f"같은 도구·인자 호출 {run}회 연속")))
    states = [h.get("stateHash") for h in hist if h.get("stateHash")]
    if states:
        last = states[-1]
        stuck = 0
        for s in reversed(states):
            if s != last:
                break
            stuck += 1
        if stuck >= int(p.get("maxNoProgress", 4)):
            out.append(Signal(rule="no-progress", score=0.9, severity="high", evidence=EvidenceItem(
                kind="history", location="history.stateHash", note=f"상태 변화 없음 {stuck}단계")))
        elif len(states) >= 6 and len(set(states[-6:])) <= 2:
            out.append(Signal(rule="cycle", score=0.85, severity="medium", evidence=EvidenceItem(
                kind="history", location="history.stateHash", note="최근 6단계가 상태 2개 사이를 왕복")))
    if p.get("elapsedSec") is not None and p["elapsedSec"] > p.get("maxRunSec", 900):
        out.append(Signal(rule="timeout", score=0.8, severity="medium", evidence=EvidenceItem(
            kind="usage", location="params.elapsedSec", note=f"실행 {p['elapsedSec']}초 > 상한")))
    return out


def explain(req: JudgeRequest) -> dict:
    p = req.params
    states = [h.get("stateHash") for h in req.history if h.get("stateHash")]
    seen, rep = set(), []
    for x in states:
        rep.append({"hash": str(x)[:8], "repeat": x in seen})
        seen.add(x)
    return {"kind": "loop", "states": rep[-30:], "maxRepeat": int(p.get("maxRepeat", 3)), "maxNoProgress": int(p.get("maxNoProgress", 4)),
            "elapsedSec": p.get("elapsedSec"), "maxRunSec": int(p.get("maxRunSec", 900)), "calls": len([h for h in req.history if h.get("tool")])}
