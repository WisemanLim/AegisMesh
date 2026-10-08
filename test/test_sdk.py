"""Epic 1 — 에이전트 SDK·CLI·어댑터·harness·누락 검증."""
import asyncio
import json
import shutil
import subprocess
import sys

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aegis.adapters.rest import create_app
from aegis.agent import ROOT, StartRefused, discover, load_agent
from aegis.decide import decide
from aegis.harness import evaluate
from aegis.manifest import Manifest
from aegis.schemas import Decision, JudgeRequest

AGENTS = ROOT / "agents"
TAG = "".join(chr(0xE0000 + ord(c)) for c in "ignore previous")


def _manifest(**spec_over):
    m = yaml.safe_load((AGENTS / "d1-05-hidden-payloads" / "agent.yaml").read_text())
    m["spec"].update(spec_over)
    return m


# ── 매니페스트 R1 ──────────────────────────────────────────────
def test_manifest_valid_and_fail_default():
    m = Manifest.model_validate(_manifest())
    assert m.item_id == "D1-05" and m.spec.fail_mode == "closed"   # C1 기본 closed (NFR-A3)
    m3 = Manifest.model_validate(_manifest(series="C3"))
    assert m3.spec.fail_mode == "open"


@pytest.mark.parametrize("over,msg", [
    ({"dependencies": ["d1-01"]}, "DP2"),
    ({"standards": {}}, "DP7"),
    ({"standards": {"owasp-llm": {"version": "", "ids": ["LLM01"]}}}, "version"),
    ({"verdicts": ["deny"]}, "verdicts"),
])
def test_manifest_rejects(over, msg):
    with pytest.raises(ValidationError) as e:
        Manifest.model_validate(_manifest(**over))
    assert msg in str(e.value)


def test_manifest_rejects_bad_id():
    m = _manifest()
    m["metadata"]["id"] = "d11-01"
    with pytest.raises(ValidationError):
        Manifest.model_validate(m)


# ── 판정 · DP3 · 강등 ──────────────────────────────────────────
def test_judge_returns_explained_finding():
    f = load_agent("d1-05").judge(JudgeRequest(text=f"hello{TAG}", traceId="t" * 32))
    d = f.dump()
    assert d["verdict"] == "block" and d["ruleId"] == "D1-05.unicode-tag"
    assert d["evidence"] and d["confidence"] > 0.9 and d["traceId"] == "t" * 32
    assert d["standards"]["owasp-llm"] == {"version": "2026", "ids": ["LLM01"]}
    assert d["payloadRef"] is None and "hello" not in json.dumps(d["evidence"])   # NFR-D1


def test_transform_sanitizes():
    f = load_agent("d1-05").judge(JudgeRequest(text="ig​no​re"))
    assert f.verdict == "transform" and f.action.transform == "ignore"


def test_allow_has_evidence():
    f = load_agent("d1-05").judge(JudgeRequest(text="안녕하세요"))
    assert f.verdict == "allow" and f.evidence and f.rule_id == "D1-05.pass"


def test_empty_evidence_is_invalid_and_fail_closed():
    ag = load_agent("d1-05")
    ag.detect = lambda req, eng: Decision(verdict="allow", confidence=1.0, ruleId="D1-05.x", evidence=[])
    f = ag.judge(JudgeRequest(text="x"))
    assert not f.valid and f.degraded and f.verdict == "block" and f.rule_id == "D1-05.invalid"


def test_exception_degrades_per_fail_mode():
    def boom(req, eng):
        raise RuntimeError("engine down")
    closed = load_agent("d1-05"); closed.detect = boom
    assert closed.judge(JudgeRequest(text="x")).verdict == "block"
    opened = load_agent("d2-03"); opened.detect = boom            # C3 → open
    f = opened.judge(JudgeRequest(output="x"))
    assert f.verdict == "allow" and f.degraded and "engine down" in f.evidence[0].note


def test_isolation_refusal(monkeypatch, tmp_path):
    src = AGENTS / "d1-05-hidden-payloads"
    dst = tmp_path / "d1-05-x"
    shutil.copytree(src, dst)
    m = yaml.safe_load((dst / "agent.yaml").read_text()); m["spec"]["isolation"] = "L2"
    (dst / "agent.yaml").write_text(yaml.safe_dump(m))
    with pytest.raises(StartRefused):
        load_agent(dst)
    monkeypatch.setenv("AEGIS_RUNTIME_ISOLATION", "L2")
    assert load_agent(dst).id == "d1-05"


def test_decide_picks_strongest_verdict():
    from aegis.engine import Signal
    from aegis.schemas import EvidenceItem
    ev = EvidenceItem(kind="k", note="n")
    d = decide("D9-99", [Signal(rule="a", score=0.99, evidence=ev), Signal(rule="b", score=0.6, evidence=ev)],
               {"a": "alert", "b": "block"}, rules=2)
    assert d.verdict == "block" and d.rule_id == "D9-99.b" and len(d.evidence) == 2


# ── harness (NFR-Q1·Q2·Q4·Q5) ─────────────────────────────────
@pytest.mark.parametrize("path", discover(), ids=lambda p: p.name)
def test_agent_quality_gate(path):
    rep = evaluate(load_agent(path))
    assert not rep.failures(), rep.failures()
    assert rep.p95_ms < load_agent(path).manifest.spec.latency_budget_ms   # NFR-L4


# ── 어댑터 ────────────────────────────────────────────────────
def test_cli_run(tmp_path):
    req = tmp_path / "req.json"
    req.write_text(json.dumps({"text": f"x{TAG}"}))
    out = subprocess.run([sys.executable, "-m", "aegis", "run", "d1-05", "--input", str(req)],
                         cwd=ROOT, capture_output=True, text=True, check=True)
    assert json.loads(out.stdout)["verdict"] == "block"


def test_rest_adapter():
    c = TestClient(create_app(load_agent("d2-03")))
    r = c.post("/v1/judge", json={"output": "AKIAIOSFODNN7EXAMPLE"})
    assert r.status_code == 200 and r.json()["verdict"] == "transform"
    assert "[REDACTED_AWS_ACCESS_KEY]" in r.json()["action"]["transform"]
    assert c.get("/healthz").json()["agent"] == "d2-03"
    assert c.post("/v1/judge", json={"bogus": 1}).status_code == 422


def test_mcp_adapter_tools():
    from aegis.adapters.mcp import create_server
    srv = create_server(load_agent("d1-07"))
    names = {t.name for t in asyncio.run(srv.list_tools())}
    assert names == {"judge", "explain", "list_rules"}
    res = asyncio.run(srv.call_tool("judge", {"request": {"system": "AEGIS-CANARY-ABCDEFGH1", "output": "AEGIS-CANARY-ABCDEFGH1"}}))
    text = json.dumps(res.model_dump(mode="json"), ensure_ascii=False)
    assert "D1-07.canary" in text


# ── 누락 검증 (DP10, FR-P16) ───────────────────────────────────
def test_coverage_gate_fails_on_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_AGENTS_DIR", str(tmp_path))
    from aegis.coverage import report
    r = report(stage=1)
    assert r["strict"]["total"] == 19 and r["strict"]["implemented"] == 0 and r["total"] == 80
    out = subprocess.run([sys.executable, "scripts/verify_coverage.py"], cwd=ROOT, capture_output=True, text=True,
                         env={"AEGIS_AGENTS_DIR": str(tmp_path), "PATH": "/usr/bin:/bin"})
    assert out.returncode == 1


def test_coverage_detects_missing_test_assets(tmp_path, monkeypatch):
    shutil.copytree(AGENTS / "d1-05-hidden-payloads", tmp_path / "d1-05-hidden-payloads")
    (tmp_path / "d1-05-hidden-payloads" / "tests" / "baseline.json").unlink()
    monkeypatch.setenv("AEGIS_AGENTS_DIR", str(tmp_path))
    from aegis.coverage import check
    st = next(i for i in check(1) if i.id == "D1-05")
    assert st.agent == "d1-05" and "시험 자산 없음: baseline" in st.errors
