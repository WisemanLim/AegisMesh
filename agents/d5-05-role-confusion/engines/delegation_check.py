"""기본 엔진: 사람·에이전트 역할 혼동 (FR-D5-05) — 대리 관계 증명, 에이전트 역할의 사람 권한 초과, 세션 중 역할 변동."""
from aegis.engine import signal
from aegis.schemas import JudgeRequest

id = "delegation_check"
PRIV = {"admin", "owner", "security-admin", "iam-admin", "finance-approver", "root"}


def scan(req: JudgeRequest):
    sub = req.subject
    human, agent = sub.principal, sub.on_behalf_of
    out = []
    if human is not None and agent is not None:
        if not req.params.get("delegation"):
            out.append(signal("no-delegation-proof", 0.75, "medium", "params.delegation", f"{agent.id} 가 {human.id} 를 대리하는 증명(위임 토큰) 없음"))
        extra = (set(agent.roles) & PRIV) - set(human.roles)
        if extra:
            out.append(signal("agent-role-exceeds-human", 0.93, "high", "subject.onBehalfOf.roles",
                              f"에이전트 특권 역할 {sorted(extra)} 이 위임자에게 없음 — 대리 실행에 쓸 수 없다"))
    roles_seen = {tuple(sorted(h.get("roles", []))) for h in req.history if h.get("principal") == (human.id if human else None) and "roles" in h}
    if len(roles_seen) > 1:
        out.append(signal("role-drift", 0.72, "medium", "history", "같은 세션에서 주체 역할이 바뀜"))
    return out


def explain(req: JudgeRequest) -> dict:
    sub = req.subject
    human, agent = sub.principal, sub.on_behalf_of
    hs, ag = set(human.scopes) if human else set(), set(agent.scopes) if agent else None
    return {"kind": "delegation", "human": human.id if human else None, "agent": agent.id if agent else None,
            "humanScopes": sorted(hs), "agentScopes": sorted(ag) if ag is not None else None,
            "effective": sorted(hs & ag) if ag is not None else sorted(hs), "delegationProof": bool(req.params.get("delegation")),
            "agentExtraRoles": sorted((set(agent.roles) & PRIV) - set(human.roles)) if human and agent else [],
            "note": "유효 권한 = 주체 ∩ 대리자. 교집합 밖 권한 요청은 차단, 주체·대리자는 판정에 분리 기록"}
