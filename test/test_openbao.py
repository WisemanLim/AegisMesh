"""Epic 41 — OpenBao 시크릿 백엔드 (FR-P07 · 원본 §1.3 발견 6): 동적 시크릿 임대의 수명·갱신·회수·만료 원본이 OpenBao.

실제 OpenBao 는 `make bao-up` 뒤 E2E(logs) 로 확인하고, 여기서는 같은 HTTP 의미의 가짜 서버로 브로커 동작을 고정한다.
"""
import secrets
import time

import pytest

from app import db, models, openbao
from app.core.config import settings


class FakeBao:
    """token 역할 aegis-lease 의미 — explicit_max_ttl 절단, accessor 로 조회·갱신·회수, 없는 accessor = 400 invalid accessor."""

    def __init__(self, max_sec: int):
        self.max, self.tokens, self.down, self.sealed, self.calls = max_sec, {}, False, False, []

    def __call__(self, method, path, body=None, auth=True):
        self.calls.append(path)
        if self.down:
            raise openbao.BaoError(503, "OpenBao 연결 실패 — fake down")
        if path.startswith("sys/health"):
            return {"sealed": self.sealed, "initialized": True, "version": "fake-2.4"}
        if self.sealed:
            raise openbao.BaoError(503, "Vault is sealed")
        now = time.time()
        acc = (body or {}).get("accessor")
        live = acc in self.tokens and self.tokens[acc]["exp"] > now
        if path == "sys/health":
            return {"sealed": False, "version": "fake-2.4"}
        if path == "auth/token/create/aegis-lease":
            ttl = min(int(body["ttl"].rstrip("s")), self.max)
            a = secrets.token_hex(12)
            self.tokens[a] = {"token": "s." + secrets.token_urlsafe(18), "exp": now + ttl, "max": now + self.max, "meta": body["meta"],
                              "policies": body["policies"]}
            return {"auth": {"client_token": self.tokens[a]["token"], "accessor": a, "lease_duration": ttl}}
        if not live:
            raise openbao.BaoError(400, "invalid accessor")
        t = self.tokens[acc]
        if path == "auth/token/lookup-accessor":
            return {"data": {"accessor": acc, "ttl": int(t["exp"] - now), "meta": t["meta"], "policies": t["policies"]}}
        if path == "auth/token/renew-accessor":
            t["exp"] = min(now + int(body["increment"].rstrip("s")), t["max"])
            return {"auth": {"lease_duration": int(t["exp"] - now)}}
        if path == "auth/token/revoke-accessor":
            del self.tokens[acc]
            return {}
        raise AssertionError(path)


@pytest.fixture
def bao(monkeypatch, client):
    assert client.post("/v1/tenants", json={"id": "bao", "name": "OpenBao 시험"}).status_code in (201, 409)
    fake = FakeBao(settings.secret_lease_max_sec)
    monkeypatch.setattr(openbao, "_call", fake)
    monkeypatch.setattr(settings, "secrets_backend", "openbao")
    monkeypatch.setattr(settings, "openbao_token", "broker-test")
    return fake


def lease(client, **kw):
    return client.post("/v1/secrets/leases", json={"path": "db/orders-ro", "scopes": ["db:read"], "tenant": "bao"} | kw)


def test_openbao_issue_introspect_renew_revoke(client, bao):
    r = lease(client, ttlSec=7200)
    assert r.status_code == 201, r.text
    j = r.json()
    secret, lid = j["secret"], j["id"]
    assert secret.startswith("s.") and j["backend"] == "openbao" and "accessor" not in j               # 원문은 OpenBao 토큰, 접근자는 비공개
    with db.system_session() as s:
        row = s.get(models.SecretLease, lid)
        assert row.backend == "openbao" and row.accessor in bao.tokens and row.secret_hash != secret
        assert (row.expires_at - row.issued_at).total_seconds() <= settings.secret_lease_max_sec      # explicit_max_ttl 절단
    meta = bao.tokens[row.accessor]["meta"]
    assert meta == {"lease": lid, "tenant": "bao", "path": "bao/db/orders-ro", "scopes": "db:read", "holder": meta["holder"]}
    ok = client.post("/v1/secrets:introspect", json={"secret": secret, "scope": "db:read"}).json()
    assert ok["active"] and ok["backend"] == "openbao" and ok["ttl"] > 0
    assert client.post("/v1/secrets:introspect", json={"secret": secret, "scope": "db:write"}).json()["active"] is False
    assert client.post(f"/v1/secrets/leases/{lid}:renew", json={"ttlSec": 60}).json()["renewals"] == 1
    assert "auth/token/renew-accessor" in bao.calls
    assert client.post(f"/v1/secrets/leases/{lid}:revoke").json()["state"] == "revoked"
    assert row.accessor not in bao.tokens                                                              # OpenBao 에서 회수됨
    assert client.post("/v1/secrets:introspect", json={"secret": secret}).json()["reason"] == "revoked"
    evs = [e["body"] for e in client.get("/v1/evidence", params={"kind": "secret", "tenant": "bao"}).json()["items"] if e["refId"] == lid]
    assert [e["event"] for e in evs] == ["lease_revoked", "lease_renewed", "lease_issued"] and all(e["backend"] == "openbao" for e in evs)


def test_openbao_is_source_of_truth(client, bao):
    j = lease(client).json()
    with db.system_session() as s:
        acc = s.get(models.SecretLease, j["id"]).accessor
    del bao.tokens[acc]                                                                                # OpenBao 쪽에서 직접 회수
    out = client.post("/v1/secrets:introspect", json={"secret": j["secret"]}).json()
    assert out["active"] is False and "OpenBao" in out["reason"]
    st = next(x for x in client.get("/v1/secrets/leases", params={"tenant": "bao"}).json()["items"] if x["id"] == j["id"])
    assert st["state"] == "revoked" and st["revokedBy"] == "openbao"                                     # 목록도 맞춘다


def test_openbao_down_fails_closed(client, bao):
    j = lease(client).json()
    bao.down = True
    r = lease(client)
    assert r.status_code == 503 and "OpenBao" in r.text
    with db.system_session() as s:
        assert not [x for x in s.query(models.SecretLease).filter_by(tenant="bao").all() if x.accessor is None and x.backend == "openbao"]
    out = client.post("/v1/secrets:introspect", json={"secret": j["secret"]}).json()
    assert out["active"] is False and "연결 실패" in out["reason"]                                      # 확인 못 하면 거부
    assert client.get("/v1/secrets/backend").json()["ok"] is False


def test_builtin_leases_still_verify_and_revoke_all_reaches_openbao(client, bao, monkeypatch):
    monkeypatch.setattr(settings, "secrets_backend", "builtin")
    old = lease(client).json()
    assert old["secret"].startswith("aeg_dyn_") and old["backend"] == "builtin"
    monkeypatch.setattr(settings, "secrets_backend", "openbao")
    new = lease(client).json()
    assert client.post("/v1/secrets:introspect", json={"secret": old["secret"]}).json()["active"]          # 전환 전 임대도 계속 확인
    assert client.get("/v1/secrets/backend").json() == {"backend": "openbao", "addr": settings.openbao_addr, "sealed": False,
                                                        "initialized": True, "version": "fake-2.4", "ok": True,
                                                        "node": settings.openbao_addr, "standby": False, "tls": False}
    from app import secrets_broker
    with db.system_session() as s:
        n = secrets_broker.revoke_all(s, "bao", "test")
        s.commit()
    assert n >= 2 and not [a for a, t in bao.tokens.items() if t["meta"]["tenant"] == "bao"]
    for x in (old, new):
        assert client.post("/v1/secrets:introspect", json={"secret": x["secret"]}).json()["active"] is False


def test_sealed_openbao_refuses_and_keeps_leases(client, bao):
    """운영형(Epic 46): 재기동 뒤 봉인 상태 = 발급 503·확인 거부·상태 sealed. 봉인 해제 뒤 같은 임대가 다시 유효(raft 저장)."""
    j = lease(client).json()
    bao.sealed = True
    st = client.get("/v1/secrets/backend").json()
    assert st["sealed"] is True and st["ok"] is False
    assert lease(client).status_code == 503
    out = client.post("/v1/secrets:introspect", json={"secret": j["secret"]}).json()
    assert out["active"] is False and "sealed" in out["reason"]
    bao.sealed = False                                                                                 # 봉인 해제
    assert client.post("/v1/secrets:introspect", json={"secret": j["secret"]}).json()["active"] is True



def test_cluster_failover_order_and_no_retry_on_timeout(monkeypatch):
    """운영형 클러스터(Epic 56): 연결 거부·이름 없음(멈춘 노드)·봉인 503 은 다음 노드, 시간 초과는 다시 보내지 않는다(발급 중복 방지)."""
    import io
    import json
    import socket
    import urllib.error
    import urllib.request

    monkeypatch.setattr(settings, "openbao_addr", "https://bao-1:8200,https://bao-2:8200,https://bao-3:8200")
    monkeypatch.setattr(settings, "openbao_token", "broker-test")
    monkeypatch.setattr(openbao, "_node", {"i": 0})
    seen, plan = [], {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout=None, context=None):
        host = req.full_url.split("/")[2].split(":")[0]
        seen.append(host)
        how = plan.get(host, "ok")
        if how == "refused":
            raise urllib.error.URLError(ConnectionRefusedError(111, "refused"))
        if how == "gone":
            raise urllib.error.URLError(socket.gaierror(-2, "Name or service not known"))
        if how == "sealed":
            raise urllib.error.HTTPError(req.full_url, 503, "sealed", {}, io.BytesIO(b'{"errors":["Vault is sealed"]}'))
        if how == "redirect":                                           # 선출 중 대기 노드 — POST 를 따라가지 않는다
            raise urllib.error.HTTPError(req.full_url, 307, "redirect", {}, io.BytesIO(b""))
        if how == "timeout":
            raise urllib.error.URLError(TimeoutError("timed out"))
        return Resp(json.dumps({"host": host}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    plan.update({"bao-1": "gone", "bao-2": "sealed"})
    assert openbao._call("GET", "sys/health")["host"] == "bao-3" and seen == ["bao-1", "bao-2", "bao-3"]
    seen.clear()
    assert openbao._call("GET", "sys/health")["host"] == "bao-3" and seen == ["bao-3"]       # 마지막으로 성공한 노드부터
    plan.update({"bao-3": "redirect", "bao-1": "ok"})
    seen.clear()
    assert openbao._call("POST", "auth/token/create/aegis-lease", {})["host"] == "bao-1" and seen == ["bao-3", "bao-1"]
    plan.update({"bao-1": "gone", "bao-3": "timeout"})
    openbao._node["i"] = 2
    seen.clear()
    with pytest.raises(openbao.BaoError):
        openbao._call("POST", "auth/token/create/aegis-lease", {})
    assert seen == ["bao-3"]
    monkeypatch.setattr(openbao.time, "sleep", lambda s: None)
    plan.update({"bao-1": "refused", "bao-2": "sealed", "bao-3": "refused"})
    seen.clear()
    with pytest.raises(openbao.BaoError) as e:
        openbao._call("GET", "sys/health")
    assert e.value.status == 503 and len(seen) == 9                                      # 미처리만 3바퀴


def test_hsm_seal_rehearsal_config_consistent():
    """Epic 68 — HSM 봉인 리허설: 노드 설정의 pkcs11 키·토큰이 토큰 준비 스크립트와 같고, 이미지는 HSM 빌드 고정 판, PIN 은 커밋하지 않는다."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    hcl = (root / "infra" / "openbao" / "hsm.hcl").read_text()
    sh = (root / "infra" / "openbao" / "hsm" / "token.sh").read_text()
    assert 'seal "pkcs11"' in hcl and 'key_label     = "bao-unseal-rsa"' in hcl and 'token_label   = "AegisMesh"' in hcl
    assert "--label bao-unseal-rsa --sensitive" in sh and "--label AegisMesh" in sh and "pin" not in hcl.split('seal "pkcs11"')[1].split("}")[0].replace("# ", "")
    assert "openbao-hsm:2.4.1@sha256:" in (root / "infra" / "openbao" / "hsm" / "Dockerfile").read_text()
    ignored = (root / ".gitignore").read_text()
    assert all(x in ignored for x in ("infra/openbao/hsm-so.pin", "infra/openbao/hsm-init.json", "infra/openbao/*.env"))
