"""Epic 11 — 거버넌스 11종 + 사건 상관(FR-P06) + 보고서(FR-P11) + 레드팀(FR-P10) + 전체 커버리지 80/80."""
import subprocess
import sys

import pytest

from aegis.agent import ROOT

T = "gov.garam.example"


def test_full_coverage_all_stages():
    out = subprocess.run([sys.executable, "scripts/verify_coverage.py", "--stage", "5"], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0 and "전체 80/80" in out.stdout and "엄격 43/43" in out.stdout, out.stdout


def test_regulated_kr_fully_resolved(client):
    d = client.get("/v1/profiles/regulated-kr").json()
    assert d["missing"] == [] and len(d["agents"]) == len(d["items"])


@pytest.fixture
def tool_agent(client):
    assert client.post("/v1/profiles/tool-agent:apply", json={"target": T}).status_code == 201


def gate(client, req, g="tool"):
    r = client.post("/v1/judge:batch", json={"gate": g, "target": T, "request": req})
    assert r.status_code == 200, r.text
    return r.json()


def test_incident_correlation(client, tool_agent):
    who = {"principal": {"id": "mallory"}}
    a = gate(client, {"tool": {"name": "run_shell", "args": {"command": "sudo su"}}, "subject": who})
    b = gate(client, {"tool": {"name": "run_shell", "args": {"command": "cat /etc/shadow"}}, "subject": who})
    assert a["incidents"] and a["incidents"] == b["incidents"]               # 같은 주체·도메인(D3) → 한 사건
    c = gate(client, {"tool": {"name": "transfer", "args": {"amount": 99_000_000}}, "subject": who})
    # 송금은 D3-01(승인 요구)과 D6-07(차단)에 동시에 걸린다 → 기존 D3 사건에 상관 + 새 D6 사건
    assert a["incidents"][0] in c["incidents"] and any(i != a["incidents"][0] for i in c["incidents"])
    inc = client.get(f"/v1/incidents/{a['incidents'][0]}").json()
    assert inc["findingCount"] >= 3 and len(inc["traceIds"]) == 3 and inc["domain"] == "D3"
    assert inc["timeline"] and inc["graph"]["nodes"] and inc["runbook"] == "d3.md" and "봉쇄" in inc["runbookText"]
    assert client.post(f"/v1/incidents/{inc['id']}:close", json={}).status_code == 409   # 봉쇄 전 종결 불가
    assert client.post(f"/v1/incidents/{inc['id']}:contain", json={"note": "에이전트 격리"}).json()["contained"]
    assert client.post(f"/v1/incidents/{inc['id']}:close", json={}).json()["status"] == "closed"
    evs = [e["body"]["event"] for e in client.get("/v1/evidence", params={"kind": "incident", "limit": 100}).json()["items"]
           if e["refId"] == inc["id"]]
    assert evs[:3] == ["closed", "contained", "correlated"] and evs[-1] == "opened"


def test_risk_register(client):
    assert client.post("/v1/risks", json={"title": "x", "decision": "accept"}).status_code == 422
    r = client.post("/v1/risks", json={"title": "dev-copilot DB 권한", "score": 7.4, "decision": "accept", "owner": "han",
                                       "dueAt": "2026-12-31T00:00:00Z"}).json()
    assert r["id"].startswith("R-") and any(x["id"] == r["id"] for x in client.get("/v1/risks").json()["items"])


def test_reports(client):
    fws = {f["id"] for f in client.get("/v1/reports").json()["items"]}
    assert fws == {"owasp-llm-2026", "owasp-asi-2026", "eu-ai-act", "pipa", "nist-ai-rmf"}
    rep = client.get("/v1/reports/owasp-llm-2026").json()
    llm01 = next(c for c in rep["controls"] if c["id"] == "LLM01")
    assert llm01["status"] == "covered" and "D1-05" in llm01["implemented"] and rep["evidence"]["ledgerOk"]
    asi = client.get("/v1/reports/owasp-asi-2026").json()
    assert all(c["items"] for c in asi["controls"])                          # ASI01~10 모두 대응 에이전트 존재
    md = client.get("/v1/reports/pipa", params={"format": "md"}).text
    assert "| §29 |" in md and "법률 판단이 아니다" in md
    assert client.get("/v1/reports/nope").status_code == 404


def test_redteam_campaign(client, anon, as_user):
    assert anon.post("/v1/redteam/campaigns:run").status_code == 401         # 이중 용도 통제: 주체 필수
    assert client.post("/v1/redteam/campaigns:run", headers=as_user("dev.lee", "developer")).status_code == 403
    r = client.post("/v1/redteam/campaigns:run").json()
    assert r["agents"] == 80 and r["regressions"] == [] and r["verdict"] == "allow"
    assert {g["group"] for g in r["fairness"]} == {"ko", "en"}
    assert client.get("/v1/redteam/campaigns").json()["items"][0]["agents"] == 80


def test_governance_assess(client):
    client.post("/v1/profiles/regulated-kr:apply", json={"target": "gov-reg.example"})
    snap = client.get("/v1/governance/snapshot").json()
    assert snap["kind"] == "governance_snapshot" and snap["ledger"]["ok"] and snap["retention"]["requiredDays"] == 1825
    r = client.post("/v1/governance:assess").json()
    rules = {h["ruleId"] for h in r["hits"]}
    assert "D10-02.retention-short" in rules                                  # 기본 보존 90일 < regulated-kr 1825일
    assert any(x.startswith("D10-07.") for x in rules)                       # OTel 수집기 미설정 경보
    assert r["verdict"] == "block"


def test_system_card(client):
    t = client.get("/v1/cards/d1-05").text
    assert "시스템 카드 — d1-05" in t and "owasp-llm 2026: LLM01" in t


def test_periodic_rescan_does_not_flood_incident(client):
    bad = {"kind": "mcp_server", "name": "flood-mcp", "signed": False, "registryApproved": False, "version": "1.0"}
    first = client.post("/v1/scan", json={"artifact": bad}).json()
    for _ in range(3):
        again = client.post("/v1/scan", json={"artifact": bad}).json()
    assert again["incidents"] == first["incidents"]
    inc = client.get(f"/v1/incidents/{first['incidents'][0]}").json()
    assert inc["findingCount"] == len([f for f in first["findings"] if f["verdict"] == "block"])   # 재점검 판정은 쌓지 않음
