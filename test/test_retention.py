"""Epic 37 — 증적 보존기한 만료 배치 (NFR-S · R07 · COMPLIANCE '감사로그 보관기간 경과 삭제 증명'):
2인 승인 · 서명 체크포인트 경계 · 법적 보존 앞까지 · 서명 삭제 증명 · 만료 뒤 체인 검증 · 구간 밖 삭제 거부."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, select

from app import db, ledger, models, retention


def _seed(chain: str, n: int, cps: tuple[int, ...], forensic_at: int | None = None, hold_ref: int | None = None) -> list[int]:
    with db.system_session() as s:
        seqs = []
        for i in range(1, n + 1):
            if forensic_at == i:
                body = {"event": "preserved", "legalHold": True, "bundle": {"records": [{"seq": seqs[hold_ref - 1], "kind": "test", "hash": "x"}]}}
                r = ledger.append(s, "forensic", "inc_test", body, chain)
            else:
                r = ledger.append(s, "test", f"r{i}", {"i": i}, chain)
            s.flush()
            seqs.append(r.seq)
            if i in cps:
                ledger.checkpoint(s, r.seq, r.hash, chain)
        s.commit()
        return seqs


@pytest.fixture
def later(monkeypatch):
    monkeypatch.setattr(retention, "_now", lambda: datetime.now(timezone.utc) + timedelta(days=4000))


def approve2(client, as_user, ref):
    for who in ("apr.r1", "apr.r2"):
        r = client.post(f"/v1/approvals/{ref}:decide", json={"decision": "approve", "reason": "보존기한 확인"}, headers=as_user(who, "approver"))
        assert r.status_code == 200, r.text
    return r.json()


def test_purge_with_two_approvals_and_certificate(client, as_user, later):
    client.post("/v1/tenants", json={"id": "rett", "name": "보존 시험", "retentionDays": 30})
    seqs = _seed("rett", 6, cps=(2, 4))
    with db.system_session() as s:                                     # 테넌트 생성 기록 2건이 체인 앞에 있다
        want = s.scalar(select(func.count()).select_from(models.Evidence).where(models.Evidence.chain == "rett", models.Evidence.seq <= seqs[3]))
    items = {x["chain"]: x for x in client.get("/v1/evidence/retention").json()["items"]}
    p = items["rett"]
    assert p["eligible"] and p["throughSeq"] == seqs[3] and p["purge"] == want >= 4 and p["retentionDays"] == 30
    assert client.post("/v1/evidence/retention:request", json={"chain": "rett"}, headers=as_user("ret.dev", "developer")).status_code == 403
    r = client.post("/v1/evidence/retention:request", json={"chain": "rett"}).json()
    assert client.post("/v1/evidence/retention:request", json={"chain": "rett"}).status_code == 409        # 대기 중
    assert approve2(client, as_user, r["approvalRef"])["status"] == "approved"
    with db.system_session() as s:
        left = list(s.scalars(select(models.Evidence.seq).where(models.Evidence.chain == "rett").order_by(models.Evidence.seq)))
    assert seqs[3] not in left and seqs[4] in left and min(left) == seqs[4]                                 # 체크포인트까지만
    v = client.get("/v1/evidence:verify?chain=rett").json()
    assert v["ok"] and v["chains"][0]["purged"]["throughSeq"] == seqs[3] and v["chains"][0]["purged"]["records"] == want
    ov = client.get("/v1/evidence/retention").json()
    pg = next(x for x in ov["purges"] if x["chain"] == "rett")
    assert pg["signatureOk"] and pg["certificate"]["records"] == want and pg["certificate"]["anchorHash"] == pg["anchorHash"] \
        and set(pg["certificate"]["approvers"]) == {"apr.r1", "apr.r2"}
    assert client.get(f"/v1/evidence/purges/{pg['id']}").json()["certificate"]["throughSeq"] == seqs[3]
    with db.system_session() as s:                                                                          # 체인 안에도 기록
        last = s.scalars(select(models.Evidence).where(models.Evidence.chain == "rett", models.Evidence.kind == "retention")
                         .order_by(models.Evidence.seq.desc())).first()
        assert last.body["event"] == "retention_purged" and last.body["records"] == want
    with db.system_session() as s, pytest.raises(Exception):                                               # 승인 구간 밖은 DB 가 거부
        s.execute(delete(models.Evidence).where(models.Evidence.chain == "rett", models.Evidence.seq == seqs[5]))
        s.commit()


def test_legal_hold_stops_purge_and_forged_certificate_fails(client, later):
    client.post("/v1/tenants", json={"id": "reth", "name": "법적 보존 시험", "retentionDays": 30})
    seqs = _seed("reth", 8, cps=(3, 6), forensic_at=7, hold_ref=5)                                          # 보존 기록이 5번을 가리킴
    p = {x["chain"]: x for x in client.get("/v1/evidence/retention").json()["items"]}["reth"]
    assert p["eligible"] and p["throughSeq"] == seqs[2] and p["legalHold"]["minSeq"] == seqs[4] and p["legalHold"]["incidents"] == ["inc_test"]
    client.post("/v1/tenants", json={"id": "retf", "name": "위조 시험", "retentionDays": 30})
    seqs = _seed("retf", 3, cps=(2,))
    with db.system_session() as s:          # 서명 없는 가짜 증명서 — 커밋하지 않는다(추가 전용이라 공유 시험 DB 에 남으면 다른 시험의 전체 검증을 깬다)
        cp = s.get(models.LedgerCheckpoint, seqs[1])
        s.add(models.LedgerPurge(id="prg_forged", chain="retf", through_seq=seqs[1], anchor_hash=cp.hash, records=2,
                                 certificate={"anchorHash": cp.hash}, signature="AAAA", key_id="x", created_at="2026-01-01T00:00:00Z"))
        s.flush()
        v = ledger.verify(s, "retf")
        s.rollback()
    assert v["ok"] is False and "삭제 증명" in v["chains"][0]["detail"]
    assert client.get("/v1/evidence:verify?chain=retf").json()["ok"] is True


def test_nothing_due_before_cutoff(client):
    client.post("/v1/tenants", json={"id": "retn", "name": "기한 전", "retentionDays": 30})
    _seed("retn", 3, cps=(2,))
    p = {x["chain"]: x for x in client.get("/v1/evidence/retention").json()["items"]}["retn"]
    assert p["eligible"] is False and "체크포인트" in p["reason"]
    assert client.post("/v1/evidence/retention:request", json={"chain": "retn"}).status_code == 409
