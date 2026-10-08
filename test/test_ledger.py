"""Epic 4 — 증적 원장(해시 체인·서명 체크포인트·내보내기·독립 검증)과 2인 승인 (FR-P05, DP9, NFR-S)."""
import copy
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aegis.agent import ROOT
from aegis.ledger_verify import verify_bundle
from app import approvals, db, ledger
from app.db import Base



def test_chain_verifies(client):
    for i in range(7):
        client.post("/v1/judge", params={"agent": "d2-03"}, json={"output": f"n{i}"})
    v = client.get("/v1/evidence:verify").json()
    assert v["ok"] and v["records"] >= 7 and v["checkpoints"] >= 1 and not v["badCheckpoints"]


def test_export_bundle_independent_verify(client, tmp_path, as_user):
    b = client.get("/v1/evidence:export", headers=as_user("auditor.park", "auditor")).json()
    ok, msg = verify_bundle(b)
    assert ok, msg
    assert b["checkpoint"]["keyId"] == client.get("/v1/evidence/public-key").json()["keyId"]
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(b, ensure_ascii=False))
    out = subprocess.run([sys.executable, "-m", "aegis", "verify-bundle", str(p)], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.startswith("OK"), out.stdout + out.stderr
    last = client.get("/v1/evidence", params={"limit": 1}).json()["items"][0]
    assert last["kind"] == "export" and last["body"]["by"] == "auditor.park"


def test_partial_range_export(client):
    """체인(default) 중간 구간 — 전역 seq 는 테넌트 체인끼리 섞여 있으므로 체인 레코드에서 구간을 고른다."""
    seqs = sorted(r["seq"] for r in client.get("/v1/evidence", params={"tenant": "default", "limit": 500}).json()["items"])
    lo, hi = seqs[2], seqs[5]
    b = client.get("/v1/evidence:export", params={"from": lo, "to": hi}).json()
    assert [r["seq"] for r in b["records"]] == seqs[2:6] and b["anchor"] != "0" * 64 and b["chain"] == "default"
    assert verify_bundle(b)[0]


@pytest.mark.parametrize("tamper,needle", [
    (lambda b: b["records"][1]["body"].update(verdict="tampered"), "해시 불일치"),   # 원래 값과 반드시 다른 값
    (lambda b: b["records"].pop(1), "prevHash"),
    (lambda b: b["checkpoint"].update(signature=b["checkpoint"]["signature"][:-4] + "AAA="), "서명"),
    (lambda b: b.update(publicKey="A" * 43 + "="), "서명"),
])
def test_tampered_bundle_fails(client, tamper, needle):
    b = copy.deepcopy(client.get("/v1/evidence:export").json())
    tamper(b)
    ok, msg = verify_bundle(b)
    assert not ok and needle in msg


def test_server_verify_detects_tamper_without_triggers(tmp_path):
    """트리거가 없는 저장소(우회 시나리오)에서도 검증이 변조를 잡는다."""
    eng = create_engine(f"sqlite:///{tmp_path}/raw.db")
    Base.metadata.create_all(eng)
    S = sessionmaker(eng)
    with S() as s:
        for i in range(3):
            ledger.append(s, "test", f"r{i}", {"i": i})
        s.commit()
        assert ledger.verify(s)["ok"]
        s.execute(Base.metadata.tables["evidence"].update().where(Base.metadata.tables["evidence"].c.seq == 2)
                  .values(body={"i": 99}))
        s.commit()
        v = ledger.verify(s)
        assert not v["ok"] and "seq 2" in v["detail"]


def test_concurrent_appends_keep_single_chain():
    def work(i):
        with db.SessionLocal() as s:
            ledger.append(s, "test", f"c{i}", {"i": i})
            s.commit()
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(work, range(40)))
    with db.SessionLocal() as s:
        assert ledger.verify(s)["ok"]


# ── 2인 승인 ───────────────────────────────────────────────────
@pytest.fixture
def approval(migrated):
    with db.SessionLocal() as s:
        row = approvals.create(s, "t" * 32, "default", "tool", ["fnd_x"], "tool 관문 승인 요청: D3-01.destructive", "dev.kim")
        s.commit()
        return row.id


@pytest.fixture
def decide(client, as_user):
    def run(aid, who, decision="approve", reason="변경 창구 승인 CHG-1"):
        return client.post(f"/v1/approvals/{aid}:decide", json={"decision": decision, "reason": reason},
                           headers=as_user(who, "approver"))
    return run


def test_two_person_approval(client, anon, approval, decide):
    assert any(a["id"] == approval for a in client.get("/v1/approvals").json()["items"])
    assert decide(approval, "dev.kim").status_code == 403                    # 본인 요청 (MSG-011)
    assert anon.post(f"/v1/approvals/{approval}:decide", json={"decision": "approve", "reason": "x"}).status_code == 401
    assert client.post(f"/v1/approvals/{approval}:decide",                    # 승인자 역할 없음(플랫폼 관리자도)
                       json={"decision": "approve", "reason": "x"}).status_code == 403
    assert decide(approval, "sec.choi", reason=" ").status_code == 422
    r = decide(approval, "sec.choi")
    assert r.status_code == 200 and r.json()["status"] == "pending"           # 1/2
    assert decide(approval, "sec.choi").status_code == 409                     # 같은 사람 두 번
    r = decide(approval, "lead.han")
    assert r.json()["status"] == "approved" and len(r.json()["decisions"]) == 2
    assert decide(approval, "cto.yoon").status_code == 409                     # 종결 후
    evs = [e for e in client.get("/v1/evidence", params={"kind": "approval"}).json()["items"] if e["refId"] == approval]
    assert [e["body"]["event"] for e in reversed(evs)] == ["requested", "decided", "decided"]


def test_reject_closes(client, approval, decide):
    r = decide(approval, "sec.choi", "reject", "운영 시간 외 요청")
    assert r.json()["status"] == "rejected"
    assert decide(approval, "lead.han").status_code == 409
    assert decide("apr_none", "lead.han").status_code == 404
