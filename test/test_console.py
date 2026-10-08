"""Epic 19 — 콘솔 보조 기능 API (SCR-B05·B06·C06·D07·R06·P02·Q02)."""
from sqlalchemy import func, select

from app import db, models


def counts():
    with db.system_session() as s:
        return tuple(s.scalar(select(func.count()).select_from(m)) for m in (models.Finding, models.Evidence, models.Approval))


def test_search(client):
    r = client.get("/v1/search", params={"q": "d1-05"}).json()
    assert any(a["id"] == "d1-05" for a in r["agents"]) and any(i["id"] == "D1-05" for i in r["items"])
    assert any(x["href"] == "/evidence" for x in client.get("/v1/search", params={"q": "증적"}).json()["screens"])
    f = client.post("/v1/judge", params={"agent": "d2-03"}, json={"output": "AKIAIOSFODNN7EXAMPLE"}).json()
    assert client.get("/v1/search", params={"q": f["traceId"]}).json()["findings"][0]["id"] == f["id"]
    assert client.get("/v1/search", params={"q": "x"}).status_code == 422


def test_notifications(client):
    r = client.get("/v1/notifications").json()
    assert set(r["counts"]) == {"critical", "high", "medium", "low", "info"}
    assert all({"at", "severity", "kind", "text", "href"} <= set(i) for i in r["items"])
    ats = [i["at"] for i in r["items"] if i["at"]]
    assert ats == sorted(ats, reverse=True)


def test_preview_replays_without_side_effects(client):
    before = counts()
    r = client.post("/v1/profiles/tool-agent:preview", json={"stage": "enforce"}).json()
    assert r["samples"] > 50 and sum(r["counts"].values()) == r["samples"]
    assert r["estimate"]["benign"] > 0 and r["estimate"]["attack"] > 0 and r["estimate"]["missRate"] is not None
    assert r["contribution"] and set(r["latency"]) <= {"input", "tool", "output"}
    obs = client.post("/v1/profiles/tool-agent:preview", json={"stage": "observe"}).json()
    assert obs["counts"]["block"] == 0 and obs["counts"]["require_approval"] == 0          # 관측만 — 차단 없음
    custom = client.post("/v1/profiles/chatbot-baseline:preview", json={"samples": [
        {"gate": "output", "label": "attack", "request": {"output": "key AKIAIOSFODNN7EXAMPLE"}}]}).json()
    assert custom["samples"] == 1 and custom["items"][0]["verdict"] == "transform"
    assert counts() == before
    assert client.post("/v1/profiles/nope:preview", json={}).status_code == 404


def test_topology_and_data_protection(client):
    t = client.get("/v1/topology").json()
    assert t["type"] == "T2" and {n["id"] for n in t["nodes"]} == {"gateway", "sandbox", "offline", "ledger", "collector", "console"}
    d = client.get("/v1/data-protection").json()
    assert d["payload"]["stored"] is False and len(d["keys"]) == 3 and d["telemetry"]["masking"] == 6


def test_rogue_terminate_blocks_and_revokes(client):
    u = client.post("/v1/users", json={"username": "rogue.bot", "kind": "service", "tenant": "default"}).json()
    tok = client.post(f"/v1/users/{u['id']}/tokens", json={"name": "leaked"}).json()["token"]
    r = client.post("/v1/rogue/rogue.bot:terminate", json={"reason": "등록부에 없는 하트비트"}).json()
    assert r["quarantine"].startswith("qtn_") and r["tokensRevoked"] == 1
    assert client.get("/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    client.post("/v1/profiles/tool-agent:apply", json={"target": "rogue.example"})
    d = client.post("/v1/judge:batch", json={"gate": "tool", "target": "rogue.example",
                                             "request": {"tool": {"name": "search_docs", "args": {"agent": "rogue.bot"}}}}).json()
    assert d["verdict"] == "block" and d["quarantine"] == r["quarantine"]


def test_redteam_run_requires_approval(client, as_user):
    assert client.post("/v1/redteam/campaigns:request", json={"agents": ["zz-99"], "reason": "x"}).status_code == 422
    r = client.post("/v1/redteam/campaigns:request", json={"agents": ["d1-05", "d2-03"], "reason": "분기 점검"}).json()
    assert r["status"] == "pending" and "L3 런타임 없음" in r["scope"]["isolation"]
    for who in ("rt.one", "rt.two"):
        d = client.post(f"/v1/approvals/{r['approvalRef']}:decide", json={"decision": "approve", "reason": "범위 확인"},
                        headers=as_user(who, "approver")).json()
    assert d["status"] == "approved"
    last = client.get("/v1/redteam/campaigns").json()["items"][0]
    assert last["agents"] == 2 and last["by"] == f"approval:{r['approvalRef']}"


def test_install_precheck(client):
    """SCR-A01·A10 — 설치 상태 실측 점검."""
    p = client.get("/v1/install/precheck").json()
    ids = {c["id"] for c in p["checks"]}
    assert {"db", "migrations", "keys", "observability", "sandbox", "worker", "admin", "coverage"} <= ids
    by = {c["id"]: c for c in p["checks"]}
    assert by["migrations"]["ok"] and by["admin"]["ok"] and by["coverage"]["ok"] and p["form"] == "docker-compose"


def test_worker_waits_for_schema(monkeypatch):
    """설치 직후 표가 없어도 worker 가 죽지 않고 기다린다(k8s 마이그레이션 Job 전 기동)."""
    from app import worker
    calls = {"n": 0}
    real = worker.db.system_session

    class Boom:
        def __enter__(self):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("no table yet")
            self.s = real()
            return self.s.__enter__()

        def __exit__(self, *a):
            return self.s.__exit__(*a) if hasattr(self, "s") else False
    monkeypatch.setattr(worker.db, "system_session", lambda: Boom())
    monkeypatch.setattr(worker.time, "sleep", lambda _s: None)
    assert worker.wait_for_schema(timeout=60) and calls["n"] == 3


def test_setup_status_and_verify(client, as_user):
    """SCR-A07~A10 — 마법사 단계 실측·설치 검증(관문 도달·기동 검사·강등 기본값·누락)."""
    st = client.get("/v1/setup/status").json()
    assert [x["key"] for x in st["steps"]] == ["admin", "identity", "evidence", "first-verdict", "verify"] and st["targetMin"] == 30
    assert st["steps"][0]["done"] and st["installedAt"]
    assert st["minutesToFirstVerdict"] is None or st["minutesToFirstVerdict"] >= 0       # 설치 이전(이관) 판정은 제외
    v = client.post("/v1/setup/verify").json()
    assert {g["gate"] for g in v["gates"]} == {"input", "tool", "output"} and all(g["ok"] for g in v["gates"])
    by = {c["id"]: c for c in v["startup"]}
    assert by["failmode"]["ok"] and by["coverage"]["ok"] and by["signature"]["ok"]
    assert client.get("/v1/setup/status").json()["steps"][4]["done"] == v["ok"]
    evs = [e["body"]["event"] for e in client.get("/v1/evidence", params={"kind": "setup", "limit": 5}).json()["items"]]
    assert "install_verified" in evs and "gate_reach" in evs
    for who, role, tenant in (("sv.ta", "tenant_admin", "default"), ("sv.eng", "security_engineer", None)):
        assert client.post("/v1/setup/verify", headers=as_user(who, role, tenant=tenant)).status_code == 403   # 플랫폼 관리자 전용
