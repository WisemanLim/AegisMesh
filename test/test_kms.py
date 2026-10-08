"""Epic 49 — 저장 암호화 (NFR-D2): 봉투 암호화·열 투명 암호화·평문 옛 행·KEK 회전·재암호화·OpenBao transit·비밀 파일.

실제 덤프 평문 0·운영형 OpenBao transit 은 리허설(prod pg_dump · bao-server)에서 확인한다.
"""
import base64
import json
import secrets
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import text

from aegis.ledger_verify import verify_bundle
from app import db, kms, ledger, mfa, models, openbao
from app.core.config import settings

CANARY = "CANARY-49-" + secrets.token_hex(4)


def raw(s, table, col, where):
    v = s.execute(text(f"SELECT {col} FROM {table} WHERE {where}")).scalar_one()
    return json.loads(v) if isinstance(v, str) and v[:1] == "{" else v


def test_seal_open_binds_context_and_detects_tamper():
    tok = kms.seal(b"secret", "users.totp_secret")
    assert kms.is_sealed(tok) and kms.open_(tok, "users.totp_secret") == b"secret" and b"secret" not in tok.encode()
    with pytest.raises(InvalidTag):
        kms.open_(tok, "policies.body")                                       # 다른 열로 옮긴 암호문은 열리지 않는다
    head, wrapped, payload = tok.split(".")
    bad = f"{head}.{wrapped}.{payload[:-2]}{'A' if payload[-2] != 'A' else 'B'}{payload[-1]}"
    with pytest.raises((InvalidTag, ValueError)):
        kms.open_(bad, "users.totp_secret")


def test_evidence_body_is_encrypted_at_rest_and_chain_still_verifies(client):
    with db.system_session() as s:
        row = ledger.append(s, "dr", "kms-test", {"note": CANARY, "by": "tester"}, tenant=ledger.PLATFORM)
        s.commit()
        seq = row.seq
        stored = raw(s, "evidence", "body", f"seq = {seq}")
        assert set(stored) == {"_enc"} and CANARY not in json.dumps(stored)
        assert s.get(models.Evidence, seq).body["note"] == CANARY                 # ORM 은 평문
        assert ledger.verify(s)["ok"]
    b = client.get("/v1/evidence:export", params={"chain": ledger.PLATFORM}).json()
    assert verify_bundle(b)[0] and any(r["body"].get("note") == CANARY for r in b["records"])   # 내보내기는 평문 + 해시 그대로


def test_anonymous_marker_keeps_governance_count(client):
    from app import governance
    with db.system_session() as s:
        before = governance.snapshot(s)["approvals"]["anonymousActions"]
        row = ledger.append(s, "dr", "kms-anon", {"by": "anonymous", "detail": CANARY}, tenant=ledger.PLATFORM)
        s.commit()
        stored = raw(s, "evidence", "body", f"seq = {row.seq}")
        assert stored["by"] == "anonymous" and CANARY not in json.dumps(stored)   # 익명 표식만 평문
        assert governance.snapshot(s)["approvals"]["anonymousActions"] == before + 1   # SQL JSON 집계가 그대로 동작


def test_legacy_plaintext_reads_and_rewrap_encrypts(client):
    with db.system_session() as s:
        p = s.query(models.Policy).first()
        body = p.body
        s.execute(text("UPDATE policies SET body = :b WHERE pk = :pk"), {"b": json.dumps(body), "pk": p.pk})   # 암호화 전 형식
        s.commit()
        assert "_enc" not in raw(s, "policies", "body", f"pk = {p.pk}")
        s.expire_all()
        assert s.get(models.Policy, p.pk).body == body                         # 평문 옛 행도 읽힌다
        assert kms.status(s)["tables"]["policies.body"]["encrypted"] < kms.status(s)["tables"]["policies.body"]["rows"]
        out = kms.rewrap(s)
        s.commit()
        assert out["policies.body"] >= 1 and "_enc" in raw(s, "policies", "body", f"pk = {p.pk}")
        t = kms.status(s)["tables"]["policies.body"]
        assert t["encrypted"] == t["rows"]


def test_builtin_kek_rotation_keeps_old_tokens(client):
    old = kms.seal(CANARY.encode(), "x")
    v = kms.rotate_builtin()
    new = kms.seal(CANARY.encode(), "x")
    assert kms.kek_of(old) != kms.kek_of(new) == f"builtin:v{v}"
    assert kms.open_(old, "x") == kms.open_(new, "x") == CANARY.encode()       # 옛 버전은 복호화 전용으로 남는다
    with db.system_session() as s:
        kms.rewrap(s)
        s.commit()
        st = kms.status(s)
    assert all(set(t["byKek"]) <= {f"builtin:v{v}"} for t in st["tables"].values())   # 수정 가능한 표는 모두 새 버전
    assert st["builtinKek"]["current"] == v and v - 1 in st["builtinKek"]["versions"]
    for f in map(Path, (settings.ledger_key_file, settings.svid_key_file, settings.auth_secret_file)):
        if f.exists():
            assert kms.kek_of(f.read_text()) == f"builtin:v{v}"                    # 비밀 파일도 새 KEK 로 재포장
    assert ledger.signing_key() and ledger.verify(db.system_session())["ok"]


def test_totp_secret_encrypted_and_legacy_seal_still_works(client):
    with db.system_session() as s:
        u = s.query(models.User).filter(models.User.username == "admin").first() or s.query(models.User).first()
        sec = mfa.totp_setup(s, u)["secret"]
        s.commit()
        stored = raw(s, "users", "totp_secret", f"id = '{u.id}'")
        assert kms.is_sealed(stored) and sec not in stored
        assert mfa.totp_check(u, mfa.totp_code(sec, int(__import__("time").time() // 30)))
        legacy = mfa.AESGCM(mfa._seal_key())
        n = b"\0" * 12
        s.execute(text("UPDATE users SET totp_secret = :v, totp_last_step = NULL WHERE id = :id"),
                  {"v": base64.urlsafe_b64encode(n + legacy.encrypt(n, sec.encode(), b"totp")).decode(), "id": u.id})
        s.commit()
        s.expire_all()
        u = s.get(models.User, u.id)
        assert mfa.totp_check(u, mfa.totp_code(sec, int(__import__("time").time() // 30) + 1))   # 옛 봉인 형식


def test_secret_file_wraps_new_and_migrates_plaintext(tmp_path):
    p = tmp_path / "k.key"
    v = kms.secret_file(p, lambda: b"fresh-secret")
    assert v == b"fresh-secret" and p.read_bytes().startswith(b"aegis1.") and b"fresh-secret" not in p.read_bytes()
    assert kms.secret_file(p, lambda: b"other") == b"fresh-secret"
    q = tmp_path / "legacy.key"
    q.write_bytes(b"\x01" * 32)
    assert kms.secret_file(q, lambda: b"x") == b"\x01" * 32 and q.read_bytes().startswith(b"aegis1.")   # 처음 읽을 때 포장본으로
    assert oct(q.stat().st_mode & 0o777) == "0o600"


class FakeTransit:
    """OpenBao transit 의미 — 버전별 키, encrypt 는 최신 버전, decrypt 는 토큰의 버전."""

    def __init__(self):
        self.keys, self.calls = {1: secrets.token_bytes(32)}, []

    def __call__(self, method, path, body=None, auth=True):
        self.calls.append(path)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if path.endswith("/rotate"):
            self.keys[max(self.keys) + 1] = secrets.token_bytes(32)
            return {}
        if path.startswith("transit/encrypt/"):
            v, n = max(self.keys), secrets.token_bytes(12)
            ct = AESGCM(self.keys[v]).encrypt(n, base64.b64decode(body["plaintext"]), None)
            return {"data": {"ciphertext": f"vault:v{v}:" + base64.b64encode(n + ct).decode()}}
        if path.startswith("transit/decrypt/"):
            _, ver, blob = body["ciphertext"].split(":", 2)
            raw_ = base64.b64decode(blob)
            return {"data": {"plaintext": base64.b64encode(AESGCM(self.keys[int(ver[1:])]).decrypt(raw_[:12], raw_[12:], None)).decode()}}
        raise openbao.BaoError(404, path)


def test_openbao_transit_backend_and_switching(monkeypatch, client):
    fake = FakeTransit()
    monkeypatch.setattr(openbao, "_call", fake)
    builtin_tok = kms.seal(b"before", "x")
    monkeypatch.setattr(settings, "kms_backend", "openbao")
    kms.reset()
    t1 = kms.seal(CANARY.encode(), "x")
    assert kms.kek_of(t1) == "openbao:v1" and "transit/encrypt/aegis-kek" in fake.calls
    assert kms.open_(builtin_tok, "x") == b"before"                             # 백엔드를 바꿔도 옛 값이 열린다(접두사로 구분)
    fake(None, "transit/keys/aegis-kek/rotate")
    kms.reset()
    t2 = kms.seal(CANARY.encode(), "x")
    assert kms.kek_of(t2) == "openbao:v2" and kms.open_(t1, "x") == kms.open_(t2, "x")
    with db.system_session() as s:
        ledger.append(s, "dr", "kms-bao", {"note": CANARY}, tenant=ledger.PLATFORM)
        s.commit()
        assert ledger.verify(s)["ok"]
    calls = len([c for c in fake.calls if c.startswith("transit/decrypt/")])
    kms.open_(t1, "x")
    assert len([c for c in fake.calls if c.startswith("transit/decrypt/")]) == calls   # 풀린 DEK 는 캐시 — 값마다 KMS 를 부르지 않는다
    kms.reset()
    monkeypatch.setattr(settings, "kms_backend", "builtin")


def test_status_api_and_no_plaintext_in_db_file(client):
    with db.system_session() as s:
        ledger.append(s, "dr", "kms-canary", {"note": CANARY}, tenant=ledger.PLATFORM)
        f = s.query(models.Finding).first()
        if f is not None:
            f.body = f.body | {"kmsCanary": CANARY}
        s.commit()
    d = client.get("/v1/observability/kms").json()
    assert d["backend"] == "builtin" and d["evidence"]["recent"]["encrypted"] >= 1
    assert all(v is True for v in d["keyFiles"].values() if v is not None)
    path = Path(settings.database_url.removeprefix("sqlite:///"))
    blob = b"".join(p.read_bytes() for p in (path, path.with_name(path.name + "-wal")) if p.exists())
    assert CANARY.encode() not in blob                                           # DB 파일(+WAL)에 평문 없음
