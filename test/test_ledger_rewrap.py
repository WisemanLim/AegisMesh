"""Epic 57 — 원장 저장 재암호화 (NFR-D2): 암호화 전 원장 기록을 2인 승인 창 안에서만 봉투 암호화로. 추가 전용 트리거는
'평문 → 암호문, 다른 열 불변, 열린 창 안' 갱신만 허용하고, 내용은 해시 체인이 그대로 검증된다."""
import secrets
import time

import pytest
import sqlalchemy as sa
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app import db, kms, ledger, ledger_rewrap, models


EV = sa.table("evidence", *(sa.column(c) for c in ("id", "kind", "ref_id", "tenant", "prev_hash", "hash", "created_at", "chain")),
              sa.column("body", sa.JSON), sa.column("seq"))


def _seed_plaintext(monkeypatch, chain: str, n: int) -> list[int]:
    """Epic 49 이전처럼 평문으로 적재 — ledger.append 와 같은 머리 잠금·해시, 저장만 평문 JSON(암호화 열 타입을 거치지 않음)."""
    out = []
    with db.system_session() as s:
        db.set_scope(s, "*")
        for i in range(n):
            head = ledger.ensure_chain(s, chain)
            head = s.execute(select(models.LedgerChain).where(models.LedgerChain.chain == chain).with_for_update()
                             .execution_options(populate_existing=True)).scalar_one()
            rec = {"id": f"evd_{secrets.token_hex(8)}", "kind": "test", "refId": f"old{i}", "tenant": chain,
                   "body": {"i": i, "note": f"legacy-canary-{i}"}, "createdAt": ledger.now_iso()}
            h = ledger.record_hash(head.hash, rec)
            s.execute(sa.insert(EV).values(id=rec["id"], kind="test", ref_id=rec["refId"], tenant=chain, body=rec["body"],
                                           prev_hash=head.hash, hash=h, created_at=rec["createdAt"], chain=chain))
            seq = s.execute(sa.select(EV.c.seq).where(EV.c.hash == h)).scalar_one()
            head.seq, head.hash, head.count = seq, h, head.count + 1
            s.flush()
            out.append(seq)
        s.commit()
    return out


def _raw(seq: int):
    with db.system_session() as s:
        return s.execute(text("SELECT body FROM evidence WHERE seq = :q"), {"q": seq}).scalar()


def _update(seq: int, sql_set: str, **kw):
    with db.system_session() as s:
        s.execute(text(f"UPDATE evidence SET {sql_set} WHERE seq = :q"), {"q": seq} | kw)
        s.commit()


def _approve2(client, as_user, ref):
    for who in ("rwp.a1", "rwp.a2"):
        r = client.post(f"/v1/approvals/{ref}:decide", json={"decision": "approve", "reason": "평문 원장 재암호화 확인"}, headers=as_user(who, "approver"))
        assert r.status_code == 200, r.text
    return r.json()


def test_trigger_blocks_updates_without_an_open_window(monkeypatch, migrated):
    seq = _seed_plaintext(monkeypatch, "default", 1)[0]
    sealed = kms.EncryptedJSON("evidence.body").process_bind_param({"i": 0, "note": "legacy-canary-0"}, None)
    import json
    with pytest.raises(DatabaseError, match="append-only"):
        _update(seq, "body = :b", b=json.dumps(sealed))                 # 창 없음
    with db.system_session() as s:                                     # 지난 창(만료)도 무효
        s.add(models.LedgerRewrap(id="rwp_expired", from_seq=seq, through_seq=seq, expires_epoch=int(time.time()) - 60, records=1,
                                  certificate={}, signature="x", key_id="k", created_at="2026-01-01T00:00:00Z"))
        s.commit()
    with pytest.raises(DatabaseError, match="append-only"):
        _update(seq, "body = :b", b=json.dumps(sealed))
    with pytest.raises(DatabaseError, match="append-only"):            # 창 표 자체도 추가 전용
        with db.system_session() as s:
            s.execute(text("UPDATE ledger_rewraps SET expires_epoch = 9999999999 WHERE id = 'rwp_expired'"))
            s.commit()


def test_two_person_window_rewraps_plaintext_and_chain_still_verifies(monkeypatch, client, as_user):
    seqs = _seed_plaintext(monkeypatch, "default", 25)
    before = {r["seq"]: r["body"] for r in client.get("/v1/evidence", params={"limit": 200}).json()["items"] if r["seq"] in seqs}
    assert all("legacy-canary" in str(_raw(q)) for q in seqs)                          # 저장값이 평문
    ov = client.get("/v1/evidence/rewrap").json()
    assert ov["plaintext"] >= 25 and ov["fromSeq"] <= seqs[0] and ov["throughSeq"] >= seqs[-1]
    assert client.post("/v1/evidence/rewrap:request", headers=as_user("rwp.dev", "developer")).status_code == 403
    r = client.post("/v1/evidence/rewrap:request").json()
    assert client.post("/v1/evidence/rewrap:request").status_code == 409              # 승인 대기 중
    with db.system_session() as s:                                                     # 승인 전 = 창 없음 = 갱신 불가
        assert ledger_rewrap.active(s) is None
    done = _approve2(client, as_user, r["approvalRef"])
    assert done["status"] == "approved"
    ov = client.get("/v1/evidence/rewrap").json()
    w = ov["windows"][0]
    assert w["active"] and w["signatureOk"] and w["certificate"]["approvers"] == ["rwp.a1", "rwp.a2"] and w["certificate"]["plaintext"] == ov["plaintext"]
    # 창 안이라도 허용되는 갱신은 '평문 → 암호문, 다른 열 불변' 하나뿐
    with pytest.raises(DatabaseError, match="append-only"):
        _update(seqs[0], "hash = :h", h="0" * 64)
    with pytest.raises(DatabaseError, match="append-only"):
        _update(seqs[0], "body = :b", b='{"i": 999, "note": "forged"}')                # 평문 → 다른 평문
    with db.system_session() as s:
        out = ledger_rewrap.run(s)
    assert out["remaining"] == 0 and out["rewrapped"] >= 25 and out["completed"]
    assert all(str(_raw(q)).startswith('{"_enc"') and "legacy-canary" not in str(_raw(q)) for q in seqs)
    with pytest.raises(DatabaseError, match="append-only"):                            # 암호문 → 암호문(다시 쓰기)도 금지
        _update(seqs[0], "body = :b", b=str(_raw(seqs[1])))
    after = {r["seq"]: r["body"] for r in client.get("/v1/evidence", params={"limit": 200}).json()["items"] if r["seq"] in seqs}
    assert after == before                                                             # 읽으면 같은 내용
    v = client.get("/v1/evidence:verify").json()
    assert v["ok"], v                                                                  # 해시 체인 그대로
    assert client.get("/v1/evidence/rewrap").json()["plaintext"] == 0
    with db.system_session() as s:
        evs = [e.body for e in s.scalars(select(models.Evidence).where(models.Evidence.kind == "kms").order_by(models.Evidence.seq))]
    assert [e["event"] for e in evs if e.get("event", "").startswith("ledger_rewrap")][-3:] == ["ledger_rewrap_requested", "ledger_rewrap_opened", "ledger_rewrapped"]
    assert kms.status(db.system_session(), full=True)["evidence"]["plaintextTotal"] == 0
    assert client.post("/v1/evidence/rewrap:request").status_code == 409               # 남은 평문 없음
