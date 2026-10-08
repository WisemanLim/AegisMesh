"""Epic 2 — 엔티티·마이그레이션·시드·레지스트리 API (FR-P03, R1)."""
import copy

import pytest
import yaml
from sqlalchemy import func, select, text
from sqlalchemy.exc import DatabaseError

from aegis.agent import ROOT
from app import db, models

BASE = yaml.safe_load((ROOT / "agents/d1-05-hidden-payloads/agent.yaml").read_text())


def manifest_for(item: str, **meta):
    m = copy.deepcopy(BASE)
    m["metadata"].update(id=item.lower(), **meta)
    return m


def test_seed_counts(migrated):
    with db.SessionLocal() as s:
        assert s.scalar(select(func.count()).select_from(models.RiskItem)) == 80
        assert s.scalar(select(func.count()).select_from(models.Agent).where(models.Agent.status == "active")) >= 3


def test_seed_idempotent(migrated):
    from app.seed import run
    again = run()
    assert again["riskItems"] == 80
    with db.SessionLocal() as s:
        assert s.scalar(select(func.count()).select_from(models.RiskItem)) == 80


def test_risk_items_map(client):
    items = client.get("/v1/risk-items").json()["items"]
    assert len(items) == 80
    by = {i["id"]: i for i in items}
    assert by["D1-05"]["agent"] == "d1-05" and by["D1-05"]["state"] in {"available", "observe", "partial", "enforce"}
    assert by["D10-07"]["agent"] == "d10-07" and by["D10-07"]["nameKo"] == "모니터링 부재"
    assert [i["id"] for i in items[:2]] == ["D1-01", "D1-02"] and items[-1]["id"] == "X10"


def test_agents_catalog(client):
    ids = {a["id"] for a in client.get("/v1/agents").json()["items"]}
    assert {"d1-05", "d1-07", "d2-03"} <= ids
    d = client.get("/v1/agents/d1-05").json()
    assert d["manifest"]["metadata"]["source"]["item"] == "Hidden payloads"
    assert d["quality"]["pass"] and d["quality"]["golden"] >= 10
    assert "D1-05.unicode-tag" in d["rules"]
    assert client.get("/v1/agents/zz-99").status_code == 404


@pytest.mark.parametrize("body,needle", [
    ({"apiVersion": "aegismesh/v1"}, "R1"),
    (manifest_for("d9-05") | {"spec": {**BASE["spec"], "dependencies": ["d1-01"]}}, "DP2"),
    (manifest_for("d1-05"), "내장 에이전트"),
])
def test_register_rejects(client, body, needle):
    r = client.post("/v1/agents", json=body)
    assert r.status_code == 422 and needle in str(r.json())


@pytest.fixture
def freed_item(migrated):
    """내장 에이전트 하나(x10)를 레지스트리에서 잠시 빼서 '미구현 항목'을 만든다. 끝나면 재동기화."""
    from sqlalchemy import delete
    from app import registry
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
    yield "x10"
    with db.SessionLocal.begin() as s:
        s.execute(delete(models.Agent).where(models.Agent.id == "x10"))
        registry.sync_builtin_agents(s)


def test_register_yaml_review_pending(client, freed_item, as_user):
    m = manifest_for(freed_item, name="Cost Observer", nameKo="비용 관측기")
    m["metadata"]["source"] = {"diagram": "AegisMesh gap analysis", "domain": "X", "item": "Cost & service-level observability"}
    r = client.post("/v1/agents", content=yaml.safe_dump(m, allow_unicode=True),
                    headers={"content-type": "application/yaml", **as_user("dev.kim", "developer")})
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["status"] == "review_pending" and d["origin"] == "api" and d["review"]["R1"] == "passed"
    with db.SessionLocal() as s:
        ev = s.scalars(select(models.Evidence).where(models.Evidence.ref_id == freed_item,
                                                     models.Evidence.kind == "agent")).all()[-1]
        assert ev.body["by"] == "dev.kim"
    # 심사 전 에이전트는 실행·바인딩 불가
    assert client.post("/v1/judge", params={"agent": freed_item}, json={}).status_code == 409


def test_register_bad_yaml(client):
    r = client.post("/v1/agents", content=b"a: [1, 2", headers={"content-type": "application/yaml"})
    assert r.status_code == 400


def test_coverage_api(client):
    assert client.get("/v1/coverage", params={"stage": 1}).json()["strict"]["total"] == 19
    assert client.get("/v1/coverage", params={"stage": 2}).json()["strict"]["total"] == 31
    assert client.get("/v1/coverage", params={"stage": 3}).json()["strict"]["total"] == 40
    r = client.get("/v1/coverage").json()                     # 기본 엄격 범위 = AEGIS_COVERAGE_STAGE(기본 5) — 전 P0
    assert r["total"] == 80 and r["implemented"] == 80 and r["strict"]["total"] == 43


def test_health_and_probes(client):
    assert client.get("/health").json()["db"]["status"] == "ok"
    assert client.get("/healthz").status_code == 200 and client.get("/readyz").status_code == 200


def test_evidence_table_is_append_only(client):
    client.post("/v1/agents", json={"bogus": 1})   # 실패 요청은 적재 없음
    with db.SessionLocal() as s:
        from app import ledger
        ledger.append(s, "test", "x", {"n": 1})
        s.commit()
    for stmt in ("UPDATE evidence SET kind='tampered'", "DELETE FROM evidence"):
        with db.engine.begin() as c, pytest.raises(DatabaseError, match="append-only"):
            c.execute(text(stmt))
