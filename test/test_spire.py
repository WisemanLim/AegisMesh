"""Epic 53 — SPIRE 연동 (FR-P07): 등록 항목 동기화·Workload API 발급(ES256)·번들 검증·즉시 회전·폐기·내장 토큰 호환. 가짜 SPIRE CLI.

실제 spire-server·spire-agent(join token·unix 증명) 연동은 리허설(make spire-up)에서 한다.
"""
import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app import db, identity, models, spire
from app.core.config import settings


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class FakeSpire:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = "kid-test-1"
        self.entries: dict[str, dict] = {}
        self.calls: list[list[str]] = []

    def jwk(self):
        n = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "jwt-svid",
                "x": _b64(n.x.to_bytes(32, "big")), "y": _b64(n.y.to_bytes(32, "big"))}

    def sign(self, sub, aud):
        now = int(time.time())
        head = _b64(json.dumps({"alg": "ES256", "kid": self.kid, "typ": "JWT"}).encode())
        body = _b64(json.dumps({"aud": aud, "exp": now + 3600, "iat": now, "iss": f"spiffe://{settings.spiffe_trust_domain}", "sub": sub}).encode())
        r, s = decode_dss_signature(self.key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        return f"{head}.{body}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def __call__(self, args):
        self.calls.append(args)
        a = {args[i]: args[i + 1] for i in range(len(args) - 1)}
        if args[:3] == ["spire-server", "entry", "show"]:
            return {"entries": [{"id": e["id"], "spiffe_id": {"trust_domain": settings.spiffe_trust_domain, "path": sid.split(settings.spiffe_trust_domain)[1]},
                                 "selectors": [{"type": "unix", "value": e["sel"].split(":", 1)[1]}], "jwt_svid_ttl": e["ttl"]}
                                for sid, e in self.entries.items()]}
        if args[:3] == ["spire-server", "entry", "create"]:
            self.entries[a["-spiffeID"]] = {"id": f"e{len(self.entries)}", "sel": a["-selector"], "ttl": int(a["-jwtSVIDTTL"])}
            return {"results": []}
        if args[:3] == ["spire-server", "entry", "delete"]:
            self.entries = {k: v for k, v in self.entries.items() if v["id"] != a["-entryID"]}
            return ""
        if args[:3] == ["spire-server", "bundle", "show"]:
            return {"keys": [self.jwk(), {"use": "x509-svid", "kty": "EC", "kid": "x509"}]}
        if args[:4] == ["spire-agent", "api", "fetch", "jwt"]:
            sid = a["-spiffeID"]
            if sid not in self.entries:
                raise spire.SpireError("no identity issued")
            return [{"svids": [{"spiffe_id": sid, "svid": self.sign(sid, a["-audience"].split(","))}]}, {"bundles": {}}]
        raise AssertionError(args)


@pytest.fixture
def fake(monkeypatch, migrated):
    f = FakeSpire()
    monkeypatch.setattr(spire, "_run", f)
    monkeypatch.setattr(settings, "identity_backend", "spire")
    spire._bundle.update({"at": 0.0, "keys": {}})
    yield f
    spire._bundle.update({"at": 0.0, "keys": {}})


def test_sync_registers_entries_with_uid_selector_and_drops_revoked(fake):
    with db.system_session() as s:
        n = identity.sync(s)
        s.commit()
        active = {r.spiffe_id for r in s.query(models.WorkloadIdentity).filter(models.WorkloadIdentity.status == "active")}
    assert n > 0 and set(fake.entries) == active and all(e["sel"] == f"unix:uid:{os.getuid()}" for e in fake.entries.values())
    victim = next(iter(sorted(fake.entries)))
    with db.system_session() as s:
        row = s.get(models.WorkloadIdentity, victim)
        row.status = "revoked"
        s.flush()
        spire.ensure({r.spiffe_id: r.ttl_sec for r in s.query(models.WorkloadIdentity) if r.status == "active"},
                     {r.spiffe_id for r in s.query(models.WorkloadIdentity) if r.status != "active"})
        s.rollback()
    assert victim not in fake.entries


def test_issue_verify_force_rotation_and_builtin_compat(fake):
    with db.system_session() as s:
        identity.sync(s)
        row = s.get(models.WorkloadIdentity, identity.spiffe("platform", "api"))
        old_builtin = identity._sign({"iss": "x", "sub": row.spiffe_id, "aud": ["aegismesh"], "iat": int(time.time()), "exp": int(time.time()) + 60})
        tok = identity.issue(s, row)
        assert json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==="))["alg"] == "ES256"
        assert identity.verify(s, tok)["sub"] == row.spiffe_id and row.expires_at is not None
        assert identity.verify(s, old_builtin)["sub"] == row.spiffe_id                    # 전환 중 내장 토큰도 만료까지
        h, b, _ = tok.split(".")
        with pytest.raises(identity.IdentityError, match="서명 불일치"):
            identity.verify(s, f"{h}.{b}.{_b64(b'x' * 64)}")
        time.sleep(1.1)
        r = identity.rotate(s, "test", force=True)
        assert r["rotated"] == 0 and r["backend"] == "spire" and r["invalidated"] > 0      # 발급은 SPIRE 몫
        with pytest.raises(identity.IdentityError, match="즉시 회전"):
            identity.verify(s, tok)
        fresh = identity.issue(s, row)
        aud = json.loads(base64.urlsafe_b64decode(fresh.split(".")[1] + "==="))["aud"]
        assert any(a.startswith("aegis-gen-") for a in aud) and identity.verify(s, fresh)   # 세대 값으로 에이전트 캐시 우회
        s.rollback()


def test_jwks_and_status(fake, client):
    with db.system_session() as s:
        identity.sync(s)
        s.commit()
    keys = client.get("/v1/identity/jwks").json()["keys"]
    assert {k["kid"] for k in keys} >= {fake.kid} and any(k.get("alg") == "EdDSA" for k in keys) and not any(k.get("use") == "x509-svid" for k in keys)
    st = client.get("/v1/identity").json()
    assert st["backend"] == "spire" and st["spire"]["ok"] and st["algorithm"] == "ES256 (SPIRE)"


def test_new_identity_is_registered_on_first_issue_and_spire_down_is_503(fake, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    with db.system_session() as s:
        row = models.WorkloadIdentity(spiffe_id="spiffe://aegismesh.local/agent/fresh", kind="agent", ref="fresh", ttl_sec=3600,
                                      rotations=0, status="active", created_at=identity.utcnow())
        tok = identity.issue(s, row)                                                # 항목이 없으면 만들고 다시 받는다
        assert row.spiffe_id in fake.entries and tok.count(".") == 2

        def down(args):
            raise spire.SpireError("SPIRE 호출 실패 — connection refused")
        monkeypatch.setattr(spire, "_run", down)
        ghost = models.WorkloadIdentity(spiffe_id="spiffe://aegismesh.local/agent/ghost", kind="agent", ref="ghost", ttl_sec=3600,
                                        rotations=0, status="active", created_at=identity.utcnow())
        with pytest.raises(identity.IdentityError) as e:
            identity.issue(s, ghost)
        assert e.value.status == 503
