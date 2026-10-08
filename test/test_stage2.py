"""Epic 7 — 2단계 에이전트 22종 통합: 커버리지 2단계, 관문 연계, regulated-kr 정책 재정의."""
import subprocess
import sys

import pytest

from aegis.agent import ROOT

T = "stage2.garam.example"
STAGE2 = {"d2-01", "d2-02", "d2-04", "d2-05", "d2-06", "d2-07", "d4-01", "d4-02", "d4-03", "d4-04", "d4-05",
          "d4-06", "d4-07", "d6-01", "d6-02", "d6-03", "d6-04", "d6-05", "d6-06", "d6-07", "x01", "x04"}


def test_coverage_stage2_gate():
    out = subprocess.run([sys.executable, "scripts/verify_coverage.py", "--stage", "2"], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0 and "엄격 31/31" in out.stdout, out.stdout


def apply(client, profile, target=T, stage=None):
    r = client.post(f"/v1/profiles/{profile}:apply", json={"target": target, **({"stage": stage} if stage else {})})
    assert r.status_code == 201, r.text
    return r.json()


def gate(client, g, req, target=T):
    r = client.post("/v1/judge:batch", json={"gate": g, "target": target, "request": req})
    assert r.status_code == 200, r.text
    return r.json()


def by(d, agent):
    return next(x for x in d["decisions"] if x["agent"] == agent)


def test_regulated_kr_binds_stage2(client):
    a = apply(client, "regulated-kr")
    assert {"d2-01", "d2-02", "d2-04", "d2-06", "d2-07", "d6-07", "x01", "x04"} <= set(a["agents"])


def test_regulated_kr_overrides_d2_01_to_block(client):
    apply(client, "regulated-kr", target="reg.example")
    d = gate(client, "output", {"output": "고객 주민번호 900101-1234568"}, target="reg.example")
    x = by(d, "d2-01")
    assert x["original"] == "transform" and x["effective"] == "block" and d["verdict"] == "block"
    assert any("override D2-01" in r for r in x["reasons"])


def test_chatbot_output_masks_pii_and_marks_ungrounded(client):
    apply(client, "chatbot-baseline", target="chat2.example")
    req = {"output": "매출은 9,000억 원이다. 문의 010-1234-5678",
           "retrieval": [{"id": "r", "text": "2026년 매출은 1,250억 원이다."}]}
    d = gate(client, "output", req, target="chat2.example")
    assert d["verdict"] == "transform"
    v = d["transformed"]["value"]
    assert "[전화번호]" in v and "[근거 미확인]" in v and "010-1234-5678" not in v


def test_tool_gate_financial_and_peer_trust(client):
    apply(client, "tool-agent", target="tool2.example")
    d = gate(client, "tool", {"tool": {"name": "wire", "args": {"amount": 50_000_000}, "approved": True},
                              "subject": {"principal": {"id": "dev.kim"}}}, target="tool2.example")
    assert d["verdict"] == "block" and by(d, "d6-07")["ruleId"] == "D6-07.over-limit"
    d = gate(client, "tool", {"tool": {"name": "call_agent", "args": {}},
                              "params": {"peer": {"kind": "a2a", "card": {"name": "x"}}}}, target="tool2.example")
    assert by(d, "x01")["effective"] == "block"


def test_input_gate_retrieval_acl(client):
    apply(client, "regulated-kr", target="acl.example")
    d = gate(client, "input", {"text": "급여 정보 요약", "subject": {"principal": {"id": "u1", "roles": ["sales"]}},
                               "retrieval": [{"id": "salary", "acl": ["role:hr"]}]}, target="acl.example")
    assert d["verdict"] == "block" and by(d, "d2-04")["ruleId"] == "D2-04.acl-denied"


@pytest.mark.parametrize("agent", sorted(STAGE2))
def test_stage2_agent_registered_active(client, agent):
    a = client.get(f"/v1/agents/{agent}").json()
    assert a["status"] == "active" and a["quality"]["pass"]
