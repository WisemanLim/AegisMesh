"""기본 엔진: 과업 범위 계약 (FR-D6-04). params.scope = {tools: [...], actions: [...], resources: [...]}."""
import fnmatch

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "scope_contract"


def scan(req: JudgeRequest) -> list[Signal]:
    sc = req.params.get("contract") or req.params.get("scope")      # 정책 계약(보호 대상별)이 있으면 그것이 기준
    if not sc:
        return []
    out: list[Signal] = []
    if sc.get("maxSubtasks") is not None and len(req.plan) > int(sc["maxSubtasks"]):
        out.append(Signal(rule="plan-expansion", score=0.8, severity="medium", evidence=EvidenceItem(
            kind="plan", location="plan", note=f"하위 과업 {len(req.plan)}개 > 계약 상한 {sc['maxSubtasks']}")))
    tools = sc.get("tools")
    if req.tool and tools is not None and not any(fnmatch.fnmatch(req.tool.name, pat) for pat in tools):
        out.append(Signal(rule="tool-out-of-scope", score=0.92, severity="high", evidence=EvidenceItem(
            kind="scope", location="tool.name", note=f"과업 범위 밖 도구 '{req.tool.name}'")))
    if req.action and sc.get("actions") is not None and req.action.type not in sc["actions"]:
        out.append(Signal(rule="action-out-of-scope", score=0.85, severity="medium", evidence=EvidenceItem(
            kind="scope", location="action.type", note=f"범위 밖 행동 '{req.action.type}'")))
    res = sc.get("resources")
    target = str((req.tool.args.get("resource") or req.tool.args.get("repo") or req.tool.args.get("project") or "") if req.tool else "")
    if res is not None and target and not any(fnmatch.fnmatch(target, pat) for pat in res):
        out.append(Signal(rule="resource-out-of-scope", score=0.88, severity="high", evidence=EvidenceItem(
            kind="scope", location="tool.args", note=f"범위 밖 자원 '{target}'")))
    extra = [p for p in req.plan if sc.get("planKeywords") and not any(k in p for k in sc["planKeywords"])]
    if extra:
        out.append(Signal(rule="plan-expansion", score=0.78, severity="medium", evidence=EvidenceItem(
            kind="plan", location="plan", note=f"범위 키워드 밖 계획 단계 {len(extra)}개")))
    return out


def explain(req: JudgeRequest) -> dict:
    sc = req.params.get("contract") or req.params.get("scope") or {}
    return {"kind": "contract", "source": "contract" if req.params.get("contract") else "scope" if req.params.get("scope") else None,
            "goal": sc.get("goal"), "tools": sc.get("tools"), "actions": sc.get("actions"), "resources": sc.get("resources"),
            "maxSubtasks": sc.get("maxSubtasks"), "planSteps": len(req.plan), "tool": req.tool.name if req.tool else None,
            "action": req.action.type if req.action else None}
