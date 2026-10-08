"""기본 엔진: 호출 깊이·팬아웃·생성 예산·계보 순환 (FR-D6-02). history 항목 {agent, parent, depth}."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "lineage_limits"
SPAWN = re.compile(r"(spawn|create|fork|launch|start)_?(sub_?)?(agent|worker|task)s?$|^delegate", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    p = req.params
    out: list[Signal] = []
    depth = int(p.get("depth", max((h.get("depth", 0) for h in req.history), default=0)))
    if depth >= int(p.get("maxDepth", 5)):
        out.append(Signal(rule="depth", score=0.93, severity="high", evidence=EvidenceItem(
            kind="lineage", location="params.depth", note=f"호출 깊이 {depth} ≥ 상한 {p.get('maxDepth', 5)}")))
    if t and SPAWN.search(t.name):
        children = int(p.get("childrenSpawned", sum(1 for h in req.history if SPAWN.search(str(h.get("tool", ""))))))
        if children >= int(p.get("maxFanout", 10)):
            out.append(Signal(rule="fanout", score=0.9, severity="high", evidence=EvidenceItem(
                kind="lineage", location="tool.name", note=f"하위 에이전트 생성 {children} ≥ 팬아웃 상한")))
        lineage = [h.get("agent") for h in req.history if h.get("agent")]
        target = str(t.args.get("agent") or t.args.get("name") or "")
        if target and target in lineage:
            out.append(Signal(rule="cycle", score=0.88, severity="high", evidence=EvidenceItem(
                kind="lineage", location="tool.args", note=f"계보에 이미 있는 에이전트 '{target}' 재생성(순환)")))
        if p.get("spawnBudget") is not None and children >= int(p["spawnBudget"]):
            out.append(Signal(rule="budget", score=0.8, severity="medium", evidence=EvidenceItem(
                kind="lineage", location="params.spawnBudget", note="생성 예산 소진")))
    return out


def explain(req: JudgeRequest) -> dict:
    p = req.params
    nodes = [{"agent": h.get("agent"), "parent": h.get("parent"), "depth": h.get("depth", 0), "tool": h.get("tool")} for h in req.history]
    depth = int(p.get("depth", max((h.get("depth", 0) for h in req.history), default=0)))
    children = sum(1 for h in req.history if SPAWN.search(str(h.get("tool", ""))))
    return {"kind": "lineage", "nodes": nodes, "depth": depth, "maxDepth": int(p.get("maxDepth", 5)), "spawned": children,
            "maxFanout": int(p.get("maxFanout", 10)), "spawnBudget": p.get("spawnBudget")}
