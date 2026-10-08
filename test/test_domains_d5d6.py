"""Epic 30 — D5·D6 상세 화면 백엔드: 보호 대상별 계약(byPrincipal)·토큰 감시(재사용)·신원·인가·위임·드리프트·
자율 레벨·과업 계약·실행 계보·지출·보상 트랜잭션."""
from app import evidence_writer


def put(client, agent, values, reason="시험", principal=None):
    r = client.put(f"/v1/agents/{agent}/config", json={"values": values, "reason": reason} | ({"principal": principal} if principal else {}))
    assert r.status_code == 200, r.text
    return r.json()


def judge(client, gate, agents, request):
    r = client.post("/v1/judge:batch", json={"gate": gate, "agents": agents, "request": request})
    assert r.status_code == 200, r.text
    return r.json()


def inspect(client, agent, request, **kw):
    r = client.post(f"/v1/agents/{agent}:inspect", json={"request": request} | kw)
    assert r.status_code == 200, r.text
    return r.json()


ACT = {"action": {"type": "draft.save", "impact": "medium"}}


def test_by_principal_contract(client):
    try:
        d = put(client, "d6-01", {"autonomyLevel": 0}, "loan-review 보수적", principal="loan-review")
        assert d["principal"] == "loan-review" and d["values"] == {"autonomyLevel": 0} and d["principals"] == ["loan-review"] and d["base"] == {}
        assert judge(client, "tool", ["d6-01"], ACT | {"subject": {"principal": {"id": "loan-review"}}})["verdict"] == "require_approval"
        assert judge(client, "tool", ["d6-01"], ACT | {"subject": {"principal": {"id": "other"}}})["verdict"] == "allow"
        put(client, "d6-01", {"autonomyLevel": 2}, "공통")                                     # 공통 값을 바꿔도 대상 계약 유지
        assert client.get("/v1/agents/d6-01/config?principal=loan-review").json()["values"] == {"autonomyLevel": 0}
        assert judge(client, "tool", ["d6-01"], ACT | {"subject": {"principal": {"id": "loan-review"}}})["verdict"] == "require_approval"
        bad = client.put("/v1/agents/d6-01/config", json={"values": {"nope": 1}, "reason": "x", "principal": "loan-review"})
        assert bad.status_code == 422
        put(client, "d6-04", {"contract": {"goal": "여신 심사 권고", "tools": ["loan.read", "score.calc"], "maxSubtasks": 2}}, "범위 계약", principal="loan-review")
        r = judge(client, "tool", ["d6-04"], {"tool": {"name": "crm.export"}, "subject": {"principal": {"id": "loan-review"}}})
        assert r["verdict"] == "block"
        assert judge(client, "tool", ["d6-04"], {"tool": {"name": "loan.read"}, "plan": ["a", "b", "c"], "subject": {"principal": {"id": "loan-review"}}})["verdict"] == "require_approval"
        evidence_writer.flush()
        a = client.get("/v1/domains/d6/autonomy?target=loan-review").json()
        assert a["contract"]["d6-01"] == {"autonomyLevel": 0} and a["contract"]["d6-04"]["contract"]["maxSubtasks"] == 2 and "loan-review" in a["targets"]
        assert a["scopeBlocks"] and a["externalUnapproved24h"] == 0
    finally:
        put(client, "d6-01", {}, "원복", principal="loan-review")
        put(client, "d6-01", {}, "원복")
        put(client, "d6-04", {}, "원복", principal="loan-review")
    assert "agentParams" not in client.get("/v1/policies/default").json()["body"]["spec"] or \
        "d6-01" not in client.get("/v1/policies/default").json()["body"]["spec"]["agentParams"]


def test_new_knobs_d5_d6(client):
    tok = {"auth": {"method": "oauth", "tokenClaims": {"sub": "x", "exp": 9999999999}}}
    assert inspect(client, "d5-06", tok)["finding"]["verdict"] == "allow"
    x = inspect(client, "d5-06", tok, draft={"requireAudience": True})
    assert x["finding"]["ruleId"] == "D5-06.audience-missing" and x["explain"]["binding"] == "bearer"
    pay = {"action": {"type": "remit", "amount": 50000}}
    assert inspect(client, "d6-07", pay, draft={"requireCompensation": True, "compensations": {"payment": "refund"}})["finding"]["ruleId"] == "D6-07.no-compensation"
    assert inspect(client, "d6-07", pay, draft={"requireCompensation": True, "compensations": {"remit": "remit.cancel"}})["finding"]["verdict"] == "allow"
    au = inspect(client, "d6-01", {"action": {"type": "mail.send", "impact": "medium", "external": True}})["explain"]
    assert au["need"] == 2 and au["level"] == 1 and au["result"] == "require_approval"


def test_token_watch_reuse_and_audience(client):
    claims = {"sub": "batch", "aud": ["payments"], "jti": "tk-e2e-30", "iat": 1000, "exp": 1300}
    for ip in ("10.0.0.1", "10.0.0.2"):
        judge(client, "input", ["d5-03", "d5-06"], {"text": "x", "subject": {"principal": {"id": "batch-report"}},
                                                    "auth": {"method": "oauth", "tokenClaims": claims}, "session": {"id": f"s-{ip}", "ip": ip}})
    evidence_writer.flush()
    d = client.get("/v1/domains/d5/tokens?hours=1").json()
    t = next(x for x in d["tokens"] if x["principal"] == "batch-report")
    assert t["status"] == "reuse" and t["nodes"] == 2 and t["lifetimeSec"] == 300 and t["token"] and len(t["token"]) == 8
    assert any(e["kind"] == "reuse" for e in d["events"]) and d["kpi"]["reuse"] >= 1
    assert "10.0.0.1" not in str(d) and "tk-e2e-30" not in str(d)                       # IP·jti 원값 없음


def test_identity_authz_drift(client):
    i = client.get("/v1/domains/d5/identity").json()
    assert i["svids"] is not None and "items" in i["svids"] and "static" in i and "binding" in i
    judge(client, "tool", ["d3-06", "d5-05"], {"tool": {"name": "repo.push", "requiredScopes": ["repo:write"]},
                                               "subject": {"principal": {"id": "kang", "scopes": ["repo:read", "repo:write", "repo:admin"]},
                                                           "onBehalfOf": {"id": "dev-copilot", "type": "agent", "scopes": ["repo:read"]}}})
    judge(client, "tool", ["d3-06"], {"tool": {"name": "repo.read", "requiredScopes": ["repo:read"]},
                                      "subject": {"principal": {"id": "kang", "scopes": ["repo:read", "repo:write", "repo:admin"]}}})
    evidence_writer.flush()
    a = client.get("/v1/domains/d5/authz").json()
    dl = next(x for x in a["delegation"] if x["agent"] == "dev-copilot")
    assert dl["effective"] == ["repo:read"] and dl["outside"] == ["repo:write"] and dl["verdict"] == "block"
    k = next(x for x in a["drift"] if x["id"] == "kang")
    assert "repo:admin" in k["unused"] and "repo:read" in k["used"]
    r = client.post("/v1/domains/d5/authz:drift-scan").json()
    assert r["principals"] >= 1 and any(h["ruleId"] == "D5-07.unused-privileged" for h in r["hits"])
    assert a["pdp"]["policy"].startswith("default@v")


def test_runs_and_budgets(client):
    hist = [{"agent": "planner", "depth": 0, "tool": "plan", "stateHash": "e90"}, {"agent": "coder", "parent": "planner", "depth": 1, "tool": "spawn_agent", "stateHash": "4bd"},
            {"agent": "coder", "parent": "planner", "depth": 1, "tool": "edit", "stateHash": "e90"}, {"agent": "coder", "depth": 1, "tool": "edit", "stateHash": "e90"},
            {"agent": "coder", "depth": 1, "tool": "edit", "stateHash": "e90"}, {"agent": "coder", "depth": 1, "tool": "edit", "stateHash": "e90"}]
    r = judge(client, "tool", ["d6-02", "d6-03"], {"tool": {"name": "edit", "args": {"file": "a"}}, "history": hist, "subject": {"principal": {"id": "dev-copilot"}}})
    assert r["verdict"] == "block"
    evidence_writer.flush()
    runs = client.get("/v1/domains/d6/runs").json()["items"]
    assert any(x["traceId"] == r["traceId"] and x["steps"] == 6 for x in runs)
    d = client.get(f"/v1/domains/d6/runs/{r['traceId']}").json()
    assert [n["agent"] for n in d["nodes"]][:2] == ["planner", "coder"] and d["states"][2]["repeat"] and "d6-03" in d["limits"]
    assert client.get("/v1/domains/d6/runs/nope").status_code == 404
    p = judge(client, "tool", ["d6-07"], {"action": {"type": "transfer", "amount": 2400000, "reversible": False}, "subject": {"principal": {"id": "loan-review-agent"}}})
    assert p["verdict"] == "require_approval" and p["approvalRef"]
    evidence_writer.flush()
    b = client.get("/v1/domains/d6/budgets").json()
    sp = next(x for x in b["spend"] if x["principal"] == "loan-review-agent")
    assert sp["pending"] >= 2400000 and any(c["approval"]["id"] == p["approvalRef"] for c in b["approvals"])
