"""Epic 54 — 보안 키 증명 체인 (OQ3 AAGUID 허용목록): MDS3 BLOB 검증(고정 루트·서명자·서명·체인)·packed 증명(체인·AAGUID 확장·MDS 상태)·
등록 API 강제. 합성 CA·증명서·BLOB 로 시험하고, 이미지에 구운 실제 스냅숏이 있으면 그것도 검증한다.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import select
from test_login_hardening import SoftAuthenticator, b64u, call, cbor, login

from app import db, fido, models, webauthn
from app.core.config import settings
from app.webauthn import unb64u

GOOD, BYPASS, OTHER = "ee882879721c491397753dfcce97072a", "b93fd961f2e6462fb12282002247de78", "2fc0579f811347eab116bb5a8db9202a"
NOW = datetime.now(timezone.utc)


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(cn, key, issuer=None, issuer_key=None, ca=False, ou=None, san=None, aaguid=None, days=(-1, 365)):
    attrs = [x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "KR"), x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test")]
    if ou:
        attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    name = x509.Name(attrs + [x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject if issuer else name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW + timedelta(days=days[0])).not_valid_after(NOW + timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    if aaguid:
        b = b.add_extension(x509.UnrecognizedExtension(fido.AAGUID_EXT, b"\x04\x10" + bytes.fromhex(aaguid)), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def _der(c):
    return c.public_bytes(Encoding.DER)


class Pki:
    """가짜 GlobalSign 루트 → 중간 → MDS 서명자, 제조사 증명 루트 2개(정상·다른 회사)."""

    def __init__(self):
        self.root_k, self.int_k, self.sig_k = _key(), _key(), _key()
        self.root = _cert("Test Root R3", self.root_k, ca=True, days=(-30, 3650))
        self.inter = _cert("Test TLS CA", self.int_k, self.root, self.root_k, ca=True)
        self.signer = _cert("mds3.fidoalliance.org", self.sig_k, self.inter, self.int_k, san="mds3.fidoalliance.org")
        self.vendor_k, self.rogue_k, self.att_k = _key(), _key(), _key()
        self.vendor = _cert("Vendor FIDO Root", self.vendor_k, ca=True, days=(-30, 3650))
        self.rogue = _cert("Rogue Root", self.rogue_k, ca=True, days=(-30, 3650))
        self.att = _cert("Vendor Key Batch 1", self.att_k, self.vendor, self.vendor_k, ou="Authenticator Attestation", aaguid=GOOD)

    def body(self):
        e = lambda a, desc, statuses: {"aaguid": f"{a[:8]}-{a[8:12]}-{a[12:16]}-{a[16:20]}-{a[20:]}", "statusReports": [{"status": s} for s in statuses],
                                       "metadataStatement": {"description": desc, "attestationTypes": ["basic_full"],
                                                             "attestationRootCertificates": [base64.b64encode(_der(self.vendor)).decode()]}}
        return {"legalHeader": "test", "no": 77, "nextUpdate": (NOW + timedelta(days=30)).date().isoformat(),
                "entries": [e(GOOD, "Vendor Key 5", ["FIDO_CERTIFIED", "FIDO_CERTIFIED_L2"]), e(BYPASS, "Leaky Key", ["FIDO_CERTIFIED", "USER_VERIFICATION_BYPASS"]),
                            {"attestationCertificateKeyIdentifiers": ["ab"], "statusReports": [], "metadataStatement": {"description": "U2F"}}]}

    def blob(self, body=None, signer=None, key=None, x5c=None):
        signer, key = signer or self.signer, key or self.sig_k
        h = b64u(json.dumps({"alg": "ES256", "typ": "JWT", "x5c": [base64.b64encode(_der(c)).decode() for c in (x5c or [signer, self.inter])]}).encode())
        p = b64u(json.dumps(body or self.body()).encode())
        r, s = decode_dss_signature(key.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256())))
        return f"{h}.{p}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def write(self, d, raw=None, fetched=NOW):
        raw = (raw or self.blob()).encode()
        os.makedirs(d, exist_ok=True)
        meta = {"url": "test", "fetchedAt": fetched.isoformat(), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        for name, data in (("blob.jwt", raw), ("root-r3.crt", _der(self.root)), ("meta.json", json.dumps(meta).encode())):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        return str(d)


@pytest.fixture(scope="module")
def pki():
    return Pki()


@pytest.fixture
def mds_dir(pki, tmp_path, monkeypatch):
    d = pki.write(tmp_path / "fido")
    monkeypatch.setattr(fido, "ROOT_SHA256", fido.fingerprint(pki.root))
    monkeypatch.setattr(settings, "fido_mds_dir", d)
    fido._cache.update({"mds": None, "error": None, "at": 0.0})
    yield d
    fido._cache.update({"mds": None, "error": None, "at": 0.0})


class SecurityKey(SoftAuthenticator):
    """packed 증명(x5c)을 내는 소프트 보안 키. aaguid·증명 키·체인·형식을 바꿔 위조를 흉내 낸다."""

    def __init__(self, aaguid=GOOD, att_key=None, x5c=None, fmt="packed", **kw):
        super().__init__(**kw)
        self.aaguid, self.att_key, self.x5c, self.fmt = aaguid, att_key, x5c, fmt

    def create(self, pk):
        out = super().create(pk)
        att = cbor_loads(out["response"]["attestationObject"])
        ad = att["authData"][:37] + bytes.fromhex(self.aaguid) + att["authData"][53:]
        cdh = hashlib.sha256(unb64u(out["response"]["clientDataJSON"])).digest()
        st = {}
        if self.fmt == "packed":
            st = {"alg": -7, "sig": (self.att_key or self.key).sign(ad + cdh, ec.ECDSA(hashes.SHA256()))}
            if self.x5c:
                st["x5c"] = [_der(c) for c in self.x5c]
        out["response"]["attestationObject"] = b64u(cbor({"fmt": self.fmt, "attStmt": st, "authData": ad}))
        return out


def cbor_loads(s):
    return webauthn.cbor_loads(unb64u(s))


def test_blob_pin_signer_signature_and_snapshot_integrity(pki, tmp_path):
    pin, at = fido.fingerprint(pki.root), NOW
    body, certs = fido.parse_blob(pki.blob(), pki.root, at, pin)
    assert body["no"] == 77 and certs[0].subject == pki.signer.subject
    with pytest.raises(fido.FidoError) as e:                                     # 고정 지문이 아닌 루트(= 실제 GlobalSign 지문)
        fido.parse_blob(pki.blob(), pki.root, at)
    assert e.value.reason == "mds_root"
    other_k = _key()                                                              # 같은 루트 아래 다른 사이트 인증서로 서명
    web = _cert("evil.example", other_k, pki.inter, pki.int_k, san="evil.example")
    with pytest.raises(fido.FidoError) as e:
        fido.parse_blob(pki.blob(signer=web, key=other_k, x5c=[web, pki.inter]), pki.root, at, pin)
    assert e.value.reason == "mds_signer"
    h, _, s = pki.blob().split(".")                                               # 본문 바꿔치기(항목 상태 세탁)
    forged = b64u(json.dumps(pki.body() | {"entries": []}).encode())
    with pytest.raises(fido.FidoError) as e:
        fido.parse_blob(f"{h}.{forged}.{s}", pki.root, at, pin)
    assert e.value.reason == "mds_signature"
    self_k = _key()                                                               # 자체 서명 '서명자'(루트로 안 이어짐)
    fake = _cert("mds3.fidoalliance.org", self_k, san="mds3.fidoalliance.org")
    with pytest.raises(fido.FidoError) as e:
        fido.parse_blob(pki.blob(signer=fake, key=self_k, x5c=[fake]), pki.root, at, pin)
    assert e.value.reason == "chain_untrusted"
    with pytest.raises(fido.FidoError) as e:                                     # 받은 시점에 이미 만료된 체인
        fido.parse_blob(pki.blob(), pki.root, NOW + timedelta(days=400), pin)
    assert e.value.reason == "chain_expired"
    d = pki.write(tmp_path / "snap")
    m = fido.read_dir(d, pin)
    assert len(m.entries) == 2 and m.problem(BYPASS) == "USER_VERIFICATION_BYPASS" and m.problem(GOOD) is None and not m.stale()
    assert m.entry(GOOD)["certification"] == "FIDO_CERTIFIED_L2"
    with open(os.path.join(d, "blob.jwt"), "ab") as f:                            # meta.json 해시와 다른 파일
        f.write(b" ")
    with pytest.raises(fido.FidoError) as e:
        fido.read_dir(d, pin)
    assert e.value.reason == "mds_format"
    with pytest.raises(fido.FidoError) as e:
        fido.read_dir(str(tmp_path / "none"), pin)
    assert e.value.reason == "mds_missing"


def test_packed_attestation_chain_and_rejections(pki, tmp_path):
    m = fido.read_dir(pki.write(tmp_path / "s"), fido.fingerprint(pki.root))
    ad = hashlib.sha256(b"rp").digest() + b"\x45" + bytes(4) + bytes.fromhex(GOOD) + b"\x00\x01x"
    cdh = hashlib.sha256(b"cd").digest()

    def att(fmt="packed", key=None, x5c=None, alg=-7):
        st = {"alg": alg, "sig": (key or pki.att_k).sign(ad + cdh, ec.ECDSA(hashes.SHA256()))}
        if x5c is not False:
            st["x5c"] = [_der(c) for c in (x5c or [pki.att])]
        return {"fmt": fmt, "attStmt": st}

    def reason(a, aaguid=GOOD, mds=m, data=ad):
        with pytest.raises(fido.FidoError) as e:
            fido.verify_attestation(a, data, cdh, aaguid, mds)
        return e.value.reason

    ok = fido.verify_attestation(att(), ad, cdh, GOOD, m)
    assert ok["model"] == "Vendor Key 5" and "Vendor FIDO Root" in ok["root"] and ok["certification"] == "FIDO_CERTIFIED_L2"
    assert reason({"fmt": "none", "attStmt": {}}) == "attestation_none"
    assert reason({"fmt": "fido-u2f", "attStmt": {}}) == "attestation_format"
    assert reason(att(key=_key(), x5c=False)) == "self_attestation"              # 자기 증명 = 증명서 없음
    assert reason(att(key=_key())) == "attestation_signature"                    # 증명서와 다른 키로 서명
    assert reason(att(), aaguid=OTHER) == "aaguid_mismatch"                      # 증명서 AAGUID 확장 ≠ 신고 AAGUID
    k = _key()                                                                    # 다른 회사 루트 체인 + 확장 없음 → 신고 AAGUID 의 루트로 안 이어짐
    rogue = _cert("Rogue Batch", k, pki.rogue, pki.rogue_k, ou="Authenticator Attestation")
    assert reason(att(key=k, x5c=[rogue])) == "chain_untrusted"
    k2 = _key()                                                                   # 같은 제조사 루트지만 MDS 가 우회를 보고한 기종
    leaky = _cert("Leaky Batch", k2, pki.vendor, pki.vendor_k, ou="Authenticator Attestation", aaguid=BYPASS)
    leaky_ad = ad[:37] + bytes.fromhex(BYPASS) + ad[53:]
    assert reason({"fmt": "packed", "attStmt": {"alg": -7, "sig": k2.sign(leaky_ad + cdh, ec.ECDSA(hashes.SHA256())), "x5c": [_der(leaky)]}},
                  aaguid=BYPASS, data=leaky_ad) == "mds_status"
    k3 = _key()
    unknown = _cert("Unknown", k3, pki.vendor, pki.vendor_k, ou="Authenticator Attestation")
    assert reason(att(key=k3, x5c=[unknown]), aaguid=OTHER) == "mds_unknown"
    k4 = _key()                                                                   # OU 요건 위반(일반 인증서)
    plain = _cert("Plain", k4, pki.vendor, pki.vendor_k, aaguid=GOOD)
    assert reason(att(key=k4, x5c=[plain])) == "attestation_cert"
    assert reason(att(), mds=None) == "mds_unavailable"


def _enroll_user(client, anon, as_user, tid, uname, aaguids):
    client.post("/v1/tenants", json={"id": tid, "name": "FIDO 시험"})
    assert client.put(f"/v1/tenants/{tid}/auth-policy", json={"mfa": "all", "aaguids": aaguids}).status_code == 200
    as_user(uname, "security_engineer", tenant=tid)
    tok = login(anon, uname).json()["token"]
    return tok


def _register(anon, tok, key):
    o = call(anon, "POST", "/v1/auth/webauthn/register:options", tok).json()
    return o, call(anon, "POST", "/v1/auth/webauthn/register", tok, json_={"ticket": o["ticket"], "credential": key.create(o["publicKey"])})


def _auth_events(uname):
    with db.system_session() as s:
        return [e.body for e in s.scalars(select(models.Evidence).where(models.Evidence.kind == "auth").order_by(models.Evidence.seq))
                if e.body.get("user") == uname]


def test_registration_enforces_attestation_for_allowlist(pki, mds_dir, client, anon, as_user):
    tok = _enroll_user(client, anon, as_user, "fidot", "fido.eng", [GOOD])
    o, r = _register(anon, tok, SecurityKey(fmt="none"))                         # AAGUID 만 흉내(자기 신고) — 증명 없음
    assert o["publicKey"]["attestation"] == "direct" and r.status_code == 422 and "증명 없음" in r.text
    _, r = _register(anon, tok, SecurityKey(x5c=None))                           # packed 자기 증명
    assert r.status_code == 422 and "자기 증명" in r.text
    _, r = _register(anon, tok, SecurityKey(att_key=pki.att_k, x5c=[pki.att], aaguid=OTHER))
    assert r.status_code == 422 and "허용목록에 없음" in r.text
    _, r = _register(anon, tok, SecurityKey(att_key=pki.att_k, x5c=[pki.att]))  # 제조사 체인 → 통과
    assert r.status_code == 201, r.text
    assert call(anon, "GET", "/v1/auth/me", tok).json()["enrollRequired"] is False
    ev = _auth_events("fido.eng")
    assert [e["reason"] for e in ev if e["event"] == "mfa_rejected"] == ["attestation_none", "self_attestation", "aaguid_not_allowed"]
    done = next(e for e in ev if e["event"] == "mfa_enrolled")
    assert done["attestation"]["model"] == "Vendor Key 5" and done["attestation"]["fmt"] == "packed"


def test_flagged_model_rejected_without_allowlist_and_status(pki, mds_dir, client, anon, as_user):
    as_user("fido.dev", "developer")
    tok = login(anon, "fido.dev").json()["token"]
    _, r = _register(anon, tok, SecurityKey(aaguid=BYPASS, fmt="none"))
    assert r.status_code == 422 and "USER_VERIFICATION_BYPASS" in r.text
    _, r = _register(anon, tok, SecurityKey(aaguid="00" * 16, fmt="none"))      # 허용목록 없음 = 소유 증명만(기존 동작)
    assert r.status_code == 201
    st = client.get("/v1/auth/mds").json()
    assert st["loaded"] and st["no"] == 77 and st["entries"] == 2 and st["flagged"] == 1 and not st["stale"] and "mds3.fidoalliance.org" in st["signer"]
    settings.fido_mds_dir = "/nonexistent"
    fido._cache.update({"mds": None, "error": None, "at": 0.0})
    st = client.get("/v1/auth/mds").json()
    assert st["loaded"] is False and "스냅숏 없음" in st["error"]


@pytest.mark.skipif(not os.path.exists("/opt/fido/blob.jwt"), reason="이미지에 MDS 스냅숏 없음")
def test_baked_snapshot_verifies_against_globalsign_r3():
    m = fido.read_dir("/opt/fido")
    assert len(m.entries) > 100 and "fidoalliance.org" in m.signer
    yubi = m.entry("cb69481e-8ff7-4039-93ec-0a2729a154a8")                       # YubiKey 5 (USB-A, firmware 5.1)
    assert yubi and yubi["roots"]


# ── Epic 62: TPM 2.0 · android-key ───────────────────────────────
def _asn(tag: int, content: bytes) -> bytes:
    n = len(content)
    ln = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + content


def _ctx(n: int, inner: bytes) -> bytes:
    """[n] EXPLICIT — 높은 태그 번호(≥ 31)는 base-128."""
    if n < 31:
        head = bytes([0xA0 | n])
    else:
        parts = []
        while n:
            parts.insert(0, (n & 0x7F) | (0x80 if parts else 0))
            n >>= 7
        head = bytes([0xBF] + parts)
    ln = len(inner)
    return head + (bytes([ln]) if ln < 128 else bytes([0x81, ln])) + inner


def _int(n: int, tag: int = 0x02) -> bytes:
    return _asn(tag, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big"))


def _key_description(challenge: bytes, origin=0, purposes=(2,), all_apps=False) -> bytes:
    tee = (_ctx(1, _asn(0x31, b"".join(_int(p) for p in purposes))) if purposes else b"") + _ctx(702, _int(origin))
    sw = _ctx(600, _asn(0x05, b"")) if all_apps else b""
    return _asn(0x30, _int(3) + _int(1, 0x0A) + _int(4) + _int(1, 0x0A) + _asn(0x04, challenge) + _asn(0x04, b"") + _asn(0x30, sw) + _asn(0x30, tee))


def _auth_data(cred_key, aaguid=GOOD) -> bytes:
    n = cred_key.public_key().public_numbers()
    cose = cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
    cid = b"cred-1"
    return hashlib.sha256(b"rp").digest() + b"\x45" + bytes(4) + bytes.fromhex(aaguid) + len(cid).to_bytes(2, "big") + cid + cose


def test_android_key_attestation(pki, tmp_path):
    m = fido.read_dir(pki.write(tmp_path / "s"), fido.fingerprint(pki.root))
    cred = _key()
    ad, cdh = _auth_data(cred), hashlib.sha256(b"cd-android").digest()

    def cert(kd, key=cred):
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Android Keystore Key")]))
             .issuer_name(pki.vendor.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=365))
             .add_extension(x509.UnrecognizedExtension(fido.KEY_DESCRIPTION, kd), critical=False))
        return b.sign(pki.vendor_k, hashes.SHA256())

    def att(kd, key=cred, signer=cred):
        return {"fmt": "android-key", "attStmt": {"alg": -7, "sig": signer.sign(ad + cdh, ec.ECDSA(hashes.SHA256())), "x5c": [_der_cert(cert(kd, key))]}}

    def reason(a):
        with pytest.raises(fido.FidoError) as e:
            fido.verify_attestation(a, ad, cdh, GOOD, m)
        return e.value.reason

    ok = fido.verify_attestation(att(_key_description(cdh)), ad, cdh, GOOD, m)
    assert ok["fmt"] == "android-key" and ok["model"] == "Vendor Key 5"
    assert reason(att(_key_description(b"x" * 32))) == "attestation_challenge"
    assert reason(att(_key_description(cdh, all_apps=True))) == "attestation_cert"
    assert reason(att(_key_description(cdh, origin=2))) == "attestation_cert"                  # 가져온 키(생성 아님)
    assert reason(att(_key_description(cdh, purposes=(3,)))) == "attestation_cert"             # 서명 용도 아님
    other = _key()
    assert reason(att(_key_description(cdh), key=other, signer=other)) == "attestation_key"    # 증명서 키 ≠ 자격 증명 키


def _der_cert(c):
    from cryptography.hazmat.primitives.serialization import Encoding
    return c.public_bytes(Encoding.DER)


def _tpm_parts(cred, aik, ad, cdh, name_tamper=False, extra=None):
    n = cred.public_key().public_numbers()
    pa = ((0x0023).to_bytes(2, "big") + (0x000B).to_bytes(2, "big") + bytes(4) + (0).to_bytes(2, "big")
          + (0x0010).to_bytes(2, "big") * 2 + (0x0003).to_bytes(2, "big") + (0x0010).to_bytes(2, "big")
          + (32).to_bytes(2, "big") + n.x.to_bytes(32, "big") + (32).to_bytes(2, "big") + n.y.to_bytes(32, "big"))
    name = (0x000B).to_bytes(2, "big") + hashlib.sha256(pa + (b"x" if name_tamper else b"")).digest()
    ex = extra if extra is not None else hashlib.sha256(ad + cdh).digest()
    ci = (b"\xffTCG" + b"\x80\x17" + (0).to_bytes(2, "big") + len(ex).to_bytes(2, "big") + ex + bytes(17) + bytes(8)
          + len(name).to_bytes(2, "big") + name + (0).to_bytes(2, "big"))
    return pa, ci, aik.sign(ci, ec.ECDSA(hashes.SHA256()))


def test_tpm_attestation(pki, tmp_path):
    m = fido.read_dir(pki.write(tmp_path / "s"), fido.fingerprint(pki.root))
    cred, aik = _key(), _key()
    ad, cdh = _auth_data(cred), hashlib.sha256(b"cd-tpm").digest()
    tcg = x509.Name([x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.1"), "id:414D4400"),
                     x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.2"), "AMD"), x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.3"), "id:00030001")])

    def aik_cert(eku=True):
        b = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(pki.vendor.subject).public_key(aik.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=365))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.SubjectAlternativeName([x509.DirectoryName(tcg)]), critical=True)
             .add_extension(x509.UnrecognizedExtension(fido.AAGUID_EXT, b"\x04\x10" + bytes.fromhex(GOOD)), critical=False))
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage([fido.TCG_AIK]), critical=False)
        return b.sign(pki.vendor_k, hashes.SHA256())

    def att(pa, ci, sig, eku=True, ver="2.0"):
        return {"fmt": "tpm", "attStmt": {"ver": ver, "alg": -7, "sig": sig, "certInfo": ci, "pubArea": pa, "x5c": [_der_cert(aik_cert(eku))]}}

    def reason(a):
        with pytest.raises(fido.FidoError) as e:
            fido.verify_attestation(a, ad, cdh, GOOD, m)
        return e.value.reason

    ok = fido.verify_attestation(att(*_tpm_parts(cred, aik, ad, cdh)), ad, cdh, GOOD, m)
    assert ok["fmt"] == "tpm" and "Vendor FIDO Root" in ok["root"]
    assert reason(att(*_tpm_parts(cred, aik, ad, cdh, extra=b"\x00" * 32))) == "attestation_challenge"
    assert reason(att(*_tpm_parts(cred, aik, ad, cdh, name_tamper=True))) == "attestation_cert"
    assert reason(att(*_tpm_parts(_key(), aik, ad, cdh))) == "attestation_key"                 # pubArea 키 ≠ 자격 증명 키
    assert reason(att(*_tpm_parts(cred, _key(), ad, cdh))) == "attestation_signature"         # 다른 키가 certInfo 서명
    assert reason(att(*_tpm_parts(cred, aik, ad, cdh), eku=False)) == "attestation_cert"
    assert reason(att(*_tpm_parts(cred, aik, ad, cdh), ver="1.2")) == "attestation_format"
