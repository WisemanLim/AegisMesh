"""기본 엔진: 객체 단위 인가 — 교차 테넌트·소유자 불일치(IDOR)·필수 역할 (FR-D5-02)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "authz_rules"
PRIVILEGED = {"admin", "support-admin", "auditor"}


def scan(req: JudgeRequest) -> list[Signal]:
    sub, res = req.subject, req.subject.resource or {}
    p = sub.principal
    out: list[Signal] = []
    if res.get("tenant") and res["tenant"] != sub.tenant:
        out.append(Signal(rule="cross-tenant", score=0.97, severity="critical", evidence=EvidenceItem(
            kind="authz", location="subject.resource.tenant", note=f"주체 테넌트 {sub.tenant} ≠ 자원 테넌트 {res['tenant']}")))
    roles = set(p.roles) if p else set()
    if res.get("owner") and p is not None and res["owner"] != p.id and not roles & PRIVILEGED:
        out.append(Signal(rule="owner-mismatch", score=0.9, severity="high", evidence=EvidenceItem(
            kind="authz", location="subject.resource.owner", note="자원 소유자가 아닌 주체의 접근(IDOR)")))
    need = set(req.params.get("requiredRoles", []))
    if need and not need & roles:
        out.append(Signal(rule="role-missing", score=0.9, severity="high", evidence=EvidenceItem(
            kind="authz", location="params.requiredRoles", note=f"필수 역할 {sorted(need)} 없음")))
    return out


def explain(req: JudgeRequest) -> dict:
    sub, res, p = req.subject, req.subject.resource or {}, req.subject.principal
    roles = set(p.roles) if p else set()
    need = sorted(req.params.get("requiredRoles", []))
    return {"kind": "authz", "principal": p.id if p else None, "roles": sorted(roles), "resource": res, "tenant": sub.tenant,
            "tenantOk": not res.get("tenant") or res["tenant"] == sub.tenant,
            "ownerOk": not res.get("owner") or p is None or res["owner"] == p.id or bool(roles & PRIVILEGED),
            "requiredRoles": need, "rolesOk": not need or bool(set(need) & roles),
            "pdp": "내장 정책 결정점(객체 단위 인가) — OPA·OpenFGA·Cerbos 로 교체 가능한 결정 인터페이스"}
