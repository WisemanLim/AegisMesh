"""Epic 14 — 정책·관문 관리 (FR-P02·P04·P15, SCR-D01~D06·C08)."""
import yaml
from sqlalchemy import func, select

from app import db, models

TOOL_REQ = {"tool": {"name": "transfer_funds", "args": {"amount": 5000}}, "subject": {"principal": {"id": "dev.pol"}}}


def doc(min_conf=0.5, overrides=None, tests=None):
    d = {"apiVersion": "aegismesh/v1", "kind": "Policy", "metadata": {"id": "default"},
         "spec": {"minConfidence": min_conf, "overrides": overrides or {}}}
    if tests is not None:
        d["tests"] = tests
    return yaml.safe_dump(d, allow_unicode=True)


def counts():
    with db.system_session() as s:
        return tuple(s.scalar(select(func.count()).select_from(m)) for m in (models.Finding, models.Evidence, models.Approval))


def test_policy_list_versions_diff(client):
    items = client.get("/v1/policies").json()["items"]
    assert any(p["id"] == "default" for p in items)
    v = client.get("/v1/policies/default/versions").json()["items"]
    assert v and "minConfidence" in v[0]["yaml"]
    other = next((x for x in v[1:] if x["yaml"] != v[0]["yaml"]), None)     # 원복 버전은 이전과 같은 본문일 수 있다
    if other:
        d = client.get("/v1/policies/default/diff", params={"from": other["version"], "to": v[0]["version"]}).json()
        assert d["diff"].startswith("--- default@v")
    assert client.get("/v1/policies/nope/versions").status_code == 404


def test_unit_tests_block_deploy(client):
    client.post("/v1/profiles/tool-agent:apply", json={"target": "pol.example"})
    bad = [{"name": "고위험 이체는 차단이어야(틀린 기대)", "gate": "tool", "request": TOOL_REQ, "target": "pol.example", "expect": "block"}]
    before = client.get("/v1/policies/default").json()["version"]
    r = client.post("/v1/policies", content=doc(0.5, tests=bad))
    assert r.status_code == 422 and r.json()["detail"]["stage"] == "unit-test"
    res = r.json()["detail"]["results"][0]
    assert not res["ok"] and res["got"] == "require_approval" and "D3-01.high-risk-tool" in res["rules"]
    assert client.get("/v1/policies/default").json()["version"] == before            # 배포 안 됨
    good = [dict(bad[0], name="고위험 이체는 승인", expect="require_approval"),
            {"name": "읽기 도구 통과", "gate": "tool", "request": {"tool": {"name": "search_docs", "args": {}}}, "target": "pol.example", "expect": "allow"}]
    dry = client.post("/v1/policies:test", content=doc(0.55, tests=good)).json()
    assert dry["passed"] == dry["total"] == 2 and "minConfidence: 0.55" in dry["diff"]
    assert client.get("/v1/policies/default").json()["version"] == before            # 시험은 저장하지 않는다
    r = client.post("/v1/policies", content=doc(0.55, tests=good))
    assert r.status_code == 201 and r.json()["tests"] == {"passed": 2, "total": 2} and r.json()["version"] == before + 1


def test_simulator_no_side_effects(client):
    client.post("/v1/profiles/tool-agent:apply", json={"target": "pol.example"})
    before = counts()
    draft = doc(0.5, overrides={"D3-01": {"verdict": "alert"}})
    r = client.post("/v1/policies:simulate", json={"gate": "tool", "request": TOOL_REQ, "target": "pol.example", "draft": draft})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["simulated"] and d["deployed"]["verdict"] == "require_approval" and d["draft"]["verdict"] == "alert"
    assert any(x["ruleId"].startswith("D3-01") and x["deployed"] == "require_approval" and x["draft"] == "alert" for x in d["changed"])
    assert "expect: alert" in d["testCase"] and any(f["ruleId"].startswith("D3-01") for f in d["findings"])
    assert counts() == before                                                          # 판정·원장·승인 무영향


def test_rollback_requires_two_approvals(client, as_user):
    vs = client.get("/v1/policies/default/versions").json()["items"]
    if len(vs) < 2:
        client.post("/v1/policies", content=doc(0.51))
        vs = client.get("/v1/policies/default/versions").json()["items"]
    latest, target = vs[0]["version"], vs[-1]["version"]
    lead = as_user("pol.lead", "security_engineer")
    r = client.post("/v1/policies/default:rollback", json={"to": target, "reason": "오탐 증가 CHG-14"}, headers=lead)
    assert r.status_code == 202 and r.json()["status"] == "pending"
    aid = r.json()["approvalRef"]
    assert client.get("/v1/policies/default").json()["version"] == latest             # 승인 전에는 그대로
    dec = lambda who: client.post(f"/v1/approvals/{aid}:decide", json={"decision": "approve", "reason": "검토 완료"},
                                  headers=as_user(who, "approver"))
    assert dec("pol.lead").status_code == 403                                          # 요청자 본인 (승인자 역할이어도)
    assert dec("rb.one").json()["status"] == "pending"
    assert dec("rb.two").json()["status"] == "approved"
    now = client.get("/v1/policies/default").json()
    assert now["version"] == latest + 1 and now["createdBy"] == f"approval:{aid}"
    v = {x["version"]: x["yaml"] for x in client.get("/v1/policies/default/versions").json()["items"]}
    assert v[latest + 1] == v[target]
    evs = [e["body"]["event"] for e in client.get("/v1/evidence", params={"kind": "approval"}).json()["items"] if e["refId"] == aid]
    assert "action_applied" in evs
    assert client.post("/v1/policies/default:rollback", json={"to": 999, "reason": "x"}).status_code == 404


def test_gates_status(client):
    client.post("/v1/profiles/tool-agent:apply", json={"target": "pol.example"})
    client.post("/v1/judge:batch", json={"gate": "tool", "request": TOOL_REQ, "target": "pol.example"})
    g = client.get("/v1/gates", params={"tenant": "default"}).json()
    tool = g["gates"]["tool"]
    assert tool["budgetMs"] == 20 and tool["hardTimeoutMs"] == 80 and tool["records"] >= 1
    d301 = next(a for a in tool["agents"] if a["id"] == "d3-01")
    assert d301["failMode"] == "closed" and d301["calls"] >= 1
    assert g["gates"]["offline"]["budgetMs"] is None and "closed" in g["failModes"]


def test_custom_profile_validate_define_scope(client, as_user):
    bad = {"apiVersion": "aegismesh/v1", "kind": "Profile", "metadata": {"id": "pay", "nameKo": "결제"},
           "spec": {"extends": "nope", "select": [{"id": ["Z9-99"]}]}}
    r = client.post("/v1/profiles:validate", content=yaml.safe_dump(bad)).json()
    assert not r["ok"] and any("nope" in e for e in r["errors"])
    good = {"apiVersion": "aegismesh/v1", "kind": "Profile", "metadata": {"id": "payments-guard", "nameKo": "결제 보호"},
            "spec": {"extends": "chatbot-baseline", "select": [{"id": ["D3-01", "D3-05"]}],
                     "policyOverrides": {"D3-05": {"verdict": "block"}}, "defaultStage": "partial"}}
    v = client.post("/v1/profiles:validate", content=yaml.safe_dump(good)).json()
    assert v["ok"] and {"d3-01", "d3-05"} <= set(v["agents"]) and "D3-01" in v["approvalItems"] and v["gates"]["tool"]["withinBudget"]
    assert client.post("/v1/profiles", content=yaml.safe_dump({**good, "spec": {**good["spec"], "bogus": 1}})).status_code == 422
    r = client.post("/v1/profiles", content=yaml.safe_dump(good))
    assert r.status_code == 201 and r.json()["id"] == "default.payments-guard"
    assert any(p["id"] == "default.payments-guard" and p["custom"] for p in client.get("/v1/profiles").json()["items"])
    a = client.post("/v1/profiles/default.payments-guard:apply", json={"target": "pay.example"}).json()
    assert a["stage"] == "partial" and "d3-05" in a["agents"]
    # 다른 테넌트 사용자에게는 보이지 않는다
    assert client.post("/v1/tenants", json={"id": "pol-t", "name": "정책 시험"}).status_code in (201, 409)
    other = as_user("pol.eng", "security_engineer", tenant="pol-t")
    assert all(p["id"] != "default.payments-guard" for p in client.get("/v1/profiles", headers=other).json()["items"])
    assert client.post("/v1/profiles/default.payments-guard:apply", json={"target": "x"}, headers=other).status_code == 404
    assert client.get("/v1/profiles/default.payments-guard", headers=other).status_code == 404
