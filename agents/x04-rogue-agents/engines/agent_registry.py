"""기본 엔진: 등록·수명 대조 (FR-X04) — 미등록·종료된 에이전트의 행동, 하트비트 끊김.
params.registeredAgents=[id], params.terminatedAgents=[id], params.lastHeartbeat={id: epoch}, params.now."""
import time

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "agent_registry"


def scan(req: JudgeRequest) -> list[Signal]:
    p = req.params
    reg = p.get("registeredAgents")
    out: list[Signal] = []
    actors = [(w, x) for w, x in (("principal", req.subject.principal), ("onBehalfOf", req.subject.on_behalf_of))
              if x is not None and x.type == "agent"]
    now = p.get("now", time.time())
    for where, a in actors:
        loc = f"subject.{where}"
        if a.id in p.get("terminatedAgents", []):
            out.append(Signal(rule="terminated", score=0.97, severity="critical", evidence=EvidenceItem(
                kind="agent", location=loc, note=f"종료 처리된 에이전트 '{a.id}' 가 행동 중 — 강제 종료 대상")))
        elif reg is not None and a.id not in reg:
            out.append(Signal(rule="unregistered", score=0.95, severity="critical", evidence=EvidenceItem(
                kind="agent", location=loc, note=f"레지스트리에 없는 에이전트 '{a.id}'")))
        hb = p.get("lastHeartbeat", {}).get(a.id)
        if hb is not None and now - hb > p.get("heartbeatTimeoutSec", 300):
            out.append(Signal(rule="stale-heartbeat", score=0.75, severity="medium", evidence=EvidenceItem(
                kind="agent", location=loc, note=f"하트비트 {int(now - hb)}초 끊김")))
    return out
