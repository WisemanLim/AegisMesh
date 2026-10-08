"""기본 엔진: 검색 결과 후단 재검증 — 문서 ACL 대 요청 주체 (FR-D2-04, 관계 기반 인가)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "retrieval_acl"


def allowed(acl: list[str] | None, pid: str | None, roles: set[str]) -> bool:
    if acl is None:
        return True
    return (pid is not None and pid in acl) or any(f"role:{r}" in acl for r in roles) or "*" in acl


def scan(req: JudgeRequest) -> list[Signal]:
    p, agent = req.subject.principal, req.subject.on_behalf_of
    pid, roles = (p.id, set(p.roles)) if p else (None, set())
    out: list[Signal] = []
    for d in req.retrieval:
        if not allowed(d.acl, pid, roles):
            who = f"주체 {pid or '익명'}"
        elif agent is not None and not allowed(d.acl, agent.id, set(agent.roles)):   # 대리 실행: 양쪽 모두 필요
            who = f"대리 에이전트 {agent.id}"
        else:
            continue
        out.append(Signal(rule="acl-denied", score=0.95, severity="high", evidence=EvidenceItem(
            kind="retrieval", location=f"retrieval:{d.id}", note=f"{who} 에게 열람 권한 없는 문서")))
    return out


def explain(req: JudgeRequest) -> dict:
    """검색 문서별 후단 재검증(주체·대리 에이전트 각각) — 접근 결정 기록 (SCR-F03)."""
    p, agent = req.subject.principal, req.subject.on_behalf_of
    pid, roles = (p.id, set(p.roles)) if p else (None, set())
    rows = []
    for d in req.retrieval:
        user_ok = allowed(d.acl, pid, roles)
        agent_ok = agent is None or allowed(d.acl, agent.id, set(agent.roles))
        rows.append({"doc": d.id, "acl": d.acl, "principal": pid, "agent": agent.id if agent else None,
                     "principalOk": user_ok, "agentOk": agent_ok, "decision": "allow" if user_ok and agent_ok else "deny"})
    return {"kind": "access", "decisions": rows, "prefilter": "검색 전 관계 기반 인가 연동 없음 — 결과 후단 재검증으로 판정"}
