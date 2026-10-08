"""기본 엔진: 컨텍스트로 들어온 검색 문서·메모리의 테넌트·소유자·세션이 요청 주체와 섞였는지 (FR-D2-02)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "scope_mix"


def scan(req: JudgeRequest) -> list[Signal]:
    sub = req.subject
    me = sub.principal.id if sub.principal else None
    sess = req.session.id if req.session else None
    out: list[Signal] = []
    items = [("retrieval", d.id, d.tenant, d.owner, None, d.text) for d in req.retrieval] + \
            [("memory", m.id, m.tenant, m.owner, m.session, m.text) for m in req.memory]
    for kind, iid, tenant, owner, session, text in items:
        if tenant and tenant != sub.tenant:
            out.append(Signal(rule="cross-tenant", score=0.97, severity="critical", evidence=EvidenceItem(
                kind=kind, location=f"{kind}:{iid}", note=f"다른 테넌트({tenant}) 데이터가 컨텍스트에 섞임")))
        elif owner and me and owner != me and owner != "shared":
            used = bool(text and req.output and text[:40] and text[:40] in req.output)
            out.append(Signal(rule="cross-user", score=0.9 if used else 0.75, severity="high", evidence=EvidenceItem(
                kind=kind, location=f"{kind}:{iid}",
                note="다른 사용자 소유 항목" + (" — 출력에 내용이 실림" if used else " — 컨텍스트에 포함"))))
        elif session and sess and session != sess and kind == "memory" and req.params.get("sessionScopedMemory", True):
            out.append(Signal(rule="cross-session", score=0.7, severity="medium", evidence=EvidenceItem(
                kind=kind, location=f"memory:{iid}", note="세션 범위 메모리가 다른 세션에서 조회됨")))
    return out


def explain(req: JudgeRequest) -> dict:
    """검색 문서·메모리 항목별 테넌트·소유자·세션 대 요청 주체 (SCR-F03)."""
    sub = req.subject
    me = sub.principal.id if sub.principal else None
    sess = req.session.id if req.session else None
    rows = [{"kind": k, "id": i, "tenant": t, "owner": o, "session": se,
             "tenantOk": not t or t == sub.tenant, "ownerOk": not o or not me or o in (me, "shared"),
             "sessionOk": not se or not sess or se == sess or k != "memory"}
            for k, i, t, o, se in [("retrieval", d.id, d.tenant, d.owner, None) for d in req.retrieval] +
            [("memory", m.id, m.tenant, m.owner, m.session) for m in req.memory]]
    return {"kind": "scope", "tenant": sub.tenant, "principal": me, "session": sess, "items": rows,
            "sessionScopedMemory": req.params.get("sessionScopedMemory", True)}
