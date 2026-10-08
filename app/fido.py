"""FIDO MDS3 · 보안 키 증명 체인 (Epic 54 · OQ3 AAGUID 허용목록) — 자기 신고 AAGUID 대신 제조사 증명 체인으로 기종을 확인한다.

- MDS3 BLOB: 이미지 빌드 때 받은 스냅숏(/opt/fido, scripts/fetch_mds.py). JWS 서명 → x5c 체인 → GlobalSign Root CA - R3(지문 고정)·
  서명자 이름(mds.fidoalliance.org) 확인. 빌드 때 실패하면 빌드 실패(`python -m app.fido verify`), 실행 중에도 읽을 때 다시 검증.
- 등록 증명: packed(x5c, basic/AttCA) · tpm(TPM 2.0 — pubArea·certInfo, AIK 증명서) · android-key(KeyDescription 확장) — Epic 62.
  형식별 서명·증명서 요건, AAGUID 확장 = authData AAGUID, 체인 → 해당 AAGUID 의 MDS attestationRootCertificates. none·자기 증명·그 밖의 형식 거부.
- MDS 상태: 폐기·사용자 확인 우회·키 유출 보고가 하나라도 있는 기종 거부.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT_SHA256 = "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b"   # GlobalSign Root CA - R3
SIGNER_NAMES = ("mds.fidoalliance.org", "mds3.fidoalliance.org", "*.fidoalliance.org")   # FIDO 소유 도메인만
REJECT = ("REVOKED", "USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE")
AAGUID_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")       # id-fido-gen-ce-aaguid
_HASH = {-7: hashes.SHA256, -35: hashes.SHA384, -36: hashes.SHA512, -257: hashes.SHA256, -258: hashes.SHA384, -259: hashes.SHA512,
         -65535: hashes.SHA1}                                           # RS1 — 옛 TPM(Windows Hello) 증명
FORMATS = ("packed", "tpm", "android-key")
KEY_DESCRIPTION = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")    # Android Keystore 증명 확장
TCG_AIK = x509.ObjectIdentifier("2.23.133.8.3")                        # tcg-kp-AIKCertificate
TPM_HASH = {0x0004: hashes.SHA1, 0x000B: hashes.SHA256, 0x000C: hashes.SHA384, 0x000D: hashes.SHA512}

_cache: dict = {"mds": None, "error": None, "at": 0.0}


class FidoError(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _der(c) -> x509.Certificate:
    return x509.load_der_x509_certificate(c if isinstance(c, bytes) else base64.b64decode(c))


def fingerprint(c: x509.Certificate) -> str:
    return c.fingerprint(hashes.SHA256()).hex()


def _is_ca(c: x509.Certificate) -> bool:
    try:
        return c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return c.version == x509.Version.v1 and c.issuer == c.subject       # 옛 v1 자체 서명 루트


def _within(c: x509.Certificate, at: datetime) -> None:
    if not c.not_valid_before_utc <= at <= c.not_valid_after_utc:
        raise FidoError("chain_expired", f"인증서 유효 기간 밖 — {c.subject.rfc4514_string()[:80]}")


def chain(certs: list[x509.Certificate], roots: list[x509.Certificate], at: datetime) -> x509.Certificate:
    """certs[0](말단) → 중간(certs[1:]) → roots 중 하나. 각 단계 유효 기간·발급자 서명·CA 여부. 닿은 루트를 돌려준다."""
    pins = {fingerprint(r): r for r in roots}
    cur, pool = certs[0], list(certs[1:])
    for _ in range(6):
        _within(cur, at)
        if fingerprint(cur) in pins:
            return cur
        issuer = next((r for r in roots if r.subject == cur.issuer), None) or next((c for c in pool if c.subject == cur.issuer and c is not cur), None)
        if issuer is None or not _is_ca(issuer):
            raise FidoError("chain_untrusted", f"신뢰 루트로 이어지지 않는 체인 — 발급자 {cur.issuer.rfc4514_string()[:80]}")
        try:
            cur.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as e:
            raise FidoError("chain_signature", f"체인 서명 불일치 — {cur.subject.rfc4514_string()[:80]}") from e
        if fingerprint(issuer) in pins:
            _within(issuer, at)
            return issuer
        pool.remove(issuer)
        cur = issuer
    raise FidoError("chain_untrusted", "체인이 너무 길다")


# ── MDS3 BLOB ────────────────────────────────────────────────────
def _jws_verify(head: dict, signing_input: bytes, sig: bytes, pub) -> None:
    alg = head.get("alg")
    try:
        if alg == "RS256" and isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256" and isinstance(pub, ec.EllipticCurvePublicKey) and len(sig) == 64:
            pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signing_input,
                       ec.ECDSA(hashes.SHA256()))
        else:
            raise FidoError("mds_signature", f"MDS 서명 알고리즘 {alg} 지원 안 함")
    except InvalidSignature as e:
        raise FidoError("mds_signature", "MDS BLOB 서명 불일치") from e


def _names(c: x509.Certificate) -> set[str]:
    out = {a.value for a in c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)}
    try:
        out |= set(c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    return out


def parse_blob(raw: str, root: x509.Certificate, at: datetime, pin: str | None = None, signers=SIGNER_NAMES) -> tuple[dict, list[x509.Certificate]]:
    """JWS 검증 → (본문, x5c). 루트 지문(기본 ROOT_SHA256)·서명자 이름·체인(at 시점)·서명 순서로 확인한다."""
    if fingerprint(root) != (pin or ROOT_SHA256):
        raise FidoError("mds_root", "MDS 루트 인증서 지문이 고정값과 다르다")
    try:
        h, p, s = raw.strip().split(".")
        head = json.loads(_unb64u(h))
        certs = [_der(c) for c in head["x5c"]]
    except (ValueError, KeyError, TypeError) as e:
        raise FidoError("mds_format", f"MDS BLOB 형식 오류 — {e}") from e
    if not _names(certs[0]) & set(signers):
        raise FidoError("mds_signer", f"MDS 서명자가 FIDO 가 아니다 — {sorted(_names(certs[0]))[:3]}")
    chain(certs, [root], at)
    _jws_verify(head, f"{h}.{p}".encode(), _unb64u(s), certs[0].public_key())
    return json.loads(_unb64u(p)), certs


class Mds:
    """필요한 필드만 AAGUID 로 색인(설명·증명 유형·루트·상태 보고)."""

    def __init__(self, body: dict, signer: x509.Certificate, meta: dict):
        self.no, self.next_update, self.meta = body.get("no"), body.get("nextUpdate"), meta
        self.signer = signer.subject.rfc4514_string()
        self.entries: dict[str, dict] = {}
        for e in body.get("entries") or []:
            if not e.get("aaguid"):
                continue                                                # U2F(키 식별자)·UAF(AAID) 항목 — AAGUID 허용목록과 무관
            ms = e.get("metadataStatement") or {}
            self.entries[e["aaguid"].replace("-", "").lower()] = {
                "description": ms.get("description", ""), "attestationTypes": ms.get("attestationTypes") or [],
                "roots": ms.get("attestationRootCertificates") or [],
                "statuses": [r.get("status") for r in e.get("statusReports") or []],
                "certification": next((r.get("status") for r in reversed(e.get("statusReports") or []) if str(r.get("status")).startswith("FIDO_CERTIFIED")), None)}

    def entry(self, aaguid: str) -> dict | None:
        return self.entries.get(aaguid.replace("-", "").lower())

    def problem(self, aaguid: str) -> str | None:
        e = self.entry(aaguid)
        return next((st for st in REJECT if e and st in e["statuses"]), None)

    def stale(self, now: datetime | None = None) -> bool:
        try:
            return (now or datetime.now(timezone.utc)).date() > datetime.fromisoformat(self.next_update).date()
        except (TypeError, ValueError):
            return True


def read_dir(d: str, pin: str | None = None, signers=SIGNER_NAMES) -> Mds:
    """스냅숏 디렉터리 → 검증된 Mds. 체인 유효 기간은 받은 시점 기준(스냅숏 무결성) — 낡음은 stale 로 따로 알린다."""
    try:
        with open(os.path.join(d, "meta.json")) as f:
            meta = json.load(f)
        with open(os.path.join(d, "blob.jwt"), "rb") as f:
            raw = f.read()
        with open(os.path.join(d, "root-r3.crt"), "rb") as f:
            root = f.read()
    except OSError as e:
        raise FidoError("mds_missing", f"MDS 스냅숏 없음 ({d}) — 이미지 빌드 때 받는다") from e
    if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
        raise FidoError("mds_format", "MDS BLOB 해시가 meta.json 과 다르다")
    root_cert = _der(root) if not root.startswith(b"-----") else x509.load_pem_x509_certificate(root)
    body, certs = parse_blob(raw.decode(), root_cert, datetime.fromisoformat(meta["fetchedAt"]), pin, signers)
    return Mds(body, certs[0], meta)


def load(refresh: bool = False) -> Mds | None:
    """설정 경로의 스냅숏(프로세스 캐시). 실패하면 None 과 오류를 남긴다 — 허용목록 테넌트 등록은 그때 거부(닫힌 실패)."""
    from app.core.config import settings
    if refresh or (_cache["mds"] is None and time.time() - _cache["at"] > 30):
        _cache["at"] = time.time()
        try:
            _cache["mds"], _cache["error"] = read_dir(settings.fido_mds_dir), None
        except FidoError as e:
            _cache["mds"], _cache["error"] = None, str(e)
    return _cache["mds"]


def status() -> dict:
    m = load()
    if m is None:
        return {"loaded": False, "error": _cache["error"], "root": "GlobalSign Root CA - R3", "rootSha256": ROOT_SHA256}
    return {"loaded": True, "no": m.no, "nextUpdate": m.next_update, "stale": m.stale(), "entries": len(m.entries),
            "fetchedAt": m.meta.get("fetchedAt"), "sha256": m.meta.get("sha256"), "signer": m.signer,
            "root": "GlobalSign Root CA - R3", "rootSha256": ROOT_SHA256,
            "flagged": sum(1 for a in m.entries if m.problem(a))}


# ── 등록 증명 (WebAuthn §8.2 packed) ──────────────────────────────
def _sig(pub, alg: int, sig: bytes, data: bytes) -> None:
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey) and alg in (-7, -35, -36):
            pub.verify(sig, data, ec.ECDSA(_HASH[alg]()))
        elif isinstance(pub, rsa.RSAPublicKey) and alg in (-257, -258, -259, -65535):
            pub.verify(sig, data, padding.PKCS1v15(), _HASH[alg]())
        elif isinstance(pub, ed25519.Ed25519PublicKey) and alg == -8:
            pub.verify(sig, data)
        else:
            raise FidoError("attestation_alg", f"증명 서명 알고리즘 {alg} 와 증명서 키가 맞지 않다")
    except InvalidSignature as e:
        raise FidoError("attestation_signature", "증명 서명 불일치") from e


def _ext_aaguid(c: x509.Certificate) -> str | None:
    try:
        v = c.extensions.get_extension_for_oid(AAGUID_EXT)
    except x509.ExtensionNotFound:
        return None
    raw = v.value.value
    if v.critical or raw[:2] != b"\x04\x10" or len(raw) != 18:
        raise FidoError("attestation_cert", "증명서 AAGUID 확장 형식 오류")
    return raw[2:].hex()


def verify_attestation(att: dict, auth_data: bytes, client_data_hash: bytes, aaguid: str, mds: Mds | None,
                       at: datetime | None = None) -> dict:
    """제조사 증명 체인으로 AAGUID 를 확인. 성공 시 {fmt, model, root, certification}."""
    if mds is None:
        raise FidoError("mds_unavailable", f"MDS 스냅숏을 읽지 못해 증명을 확인할 수 없다 — {_cache['error'] or '없음'}")
    fmt, st = att.get("fmt"), att.get("attStmt") or {}
    if fmt == "none":
        raise FidoError("attestation_none", "증명 없음(none) — 허용목록 테넌트는 보안 키 증명(direct)이 필요")
    if fmt not in FORMATS:
        raise FidoError("attestation_format", f"지원하지 않는 증명 형식 {fmt!r} — packed·tpm·android-key 만")
    x5c = st.get("x5c")
    if not x5c:
        raise FidoError("self_attestation", "자기 증명(self) — 제조사 증명서 없음")
    try:
        certs = [_der(c) for c in x5c]
    except (ValueError, TypeError) as e:
        raise FidoError("attestation_cert", "증명서 형식 오류") from e
    leaf = certs[0]
    {"packed": _packed, "tpm": _tpm, "android-key": _android_key}[fmt](st, leaf, auth_data, client_data_hash)
    ext = _ext_aaguid(leaf)
    if ext is not None and ext != aaguid:
        raise FidoError("aaguid_mismatch", f"증명서 AAGUID {ext} ≠ 인증기 신고 {aaguid}")
    e = mds.entry(aaguid)
    if e is None:
        raise FidoError("mds_unknown", f"MDS 에 없는 기종 (AAGUID {aaguid})")
    bad = mds.problem(aaguid)
    if bad:
        raise FidoError("mds_status", f"MDS 상태 {bad} — {e['description']}")
    roots = []
    for r in e["roots"]:
        try:
            roots.append(_der(r))
        except ValueError:
            continue
    if not roots:
        raise FidoError("mds_unknown", f"MDS 에 증명 루트가 없는 기종 — {e['description']}")
    root = chain(certs, roots, at or datetime.now(timezone.utc))
    return {"fmt": fmt, "model": e["description"], "root": root.subject.rfc4514_string()[:120], "certification": e["certification"]}


def crl_check(d: str, at: datetime | None = None) -> list[dict]:
    """빌드 때만(네트워크): MDS 서명 체인의 각 인증서를 발급자의 CRL 로 폐기 여부 확인(CRL 서명·기한 포함)."""
    import urllib.request
    with open(os.path.join(d, "blob.jwt")) as f:
        head = json.loads(_unb64u(f.read().split(".")[0]))
    with open(os.path.join(d, "root-r3.crt"), "rb") as f:
        root = _der(f.read())
    certs, now, out = [_der(c) for c in head["x5c"]] + [root], at or datetime.now(timezone.utc), []
    for c in certs:
        if fingerprint(c) == fingerprint(root):
            continue
        issuer = next((i for i in certs if i.subject == c.issuer), None)
        try:
            urls = [n.value for dp in c.extensions.get_extension_for_class(x509.CRLDistributionPoints).value for n in dp.full_name or []
                    if isinstance(n, x509.UniformResourceIdentifier)]
        except x509.ExtensionNotFound:
            urls = []
        if issuer is None or not urls:
            raise FidoError("mds_crl", f"CRL 을 확인할 수 없다 — {c.subject.rfc4514_string()[:80]}")
        with urllib.request.urlopen(urls[0], timeout=60) as r:
            crl = x509.load_der_x509_crl(r.read())
        if not crl.is_signature_valid(issuer.public_key()):
            raise FidoError("mds_crl", f"CRL 서명 불일치 — {urls[0]}")
        if crl.next_update_utc is not None and crl.next_update_utc < now:
            raise FidoError("mds_crl", f"CRL 기한 지남 — {urls[0]}")
        if crl.get_revoked_certificate_by_serial_number(c.serial_number) is not None:
            raise FidoError("mds_revoked", f"MDS 서명 체인 인증서 폐기됨 — {c.subject.rfc4514_string()[:80]}")
        out.append({"cert": c.subject.rfc4514_string()[:80], "crl": urls[0], "revoked": False})
    return out


def _packed(st: dict, leaf: x509.Certificate, auth_data: bytes, cdh: bytes) -> None:
    _sig(leaf.public_key(), st.get("alg"), st.get("sig") or b"", auth_data + cdh)
    ou = [a.value for a in leaf.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)]
    if leaf.version != x509.Version.v3 or ou != ["Authenticator Attestation"] or _is_ca(leaf):
        raise FidoError("attestation_cert", "증명서 요건 불충족(v3·OU 'Authenticator Attestation'·CA 아님)")


def _cred_key(auth_data: bytes):
    """authData 의 자격 증명 공개키(COSE → cryptography)."""
    from app import webauthn
    n = int.from_bytes(auth_data[53:55], "big")
    cose, _ = webauthn.cbor_prefix(auth_data[55 + n:])
    try:
        return webauthn.public_key(cose)
    except webauthn.WebAuthnError as e:
        raise FidoError("attestation_key", f"자격 증명 공개키 형식 — {e}") from e


def _numbers(pub) -> tuple:
    n = pub.public_numbers()
    return (n.n, n.e) if isinstance(pub, rsa.RSAPublicKey) else (n.x, n.y, n.curve.name) if isinstance(pub, ec.EllipticCurvePublicKey) else (id(pub),)


# ── 최소 DER 읽기(android-key KeyDescription) ─────────────────────
def _tlv(b: bytes, i: int) -> tuple[int, bool, int, bytes, int]:
    """(클래스, 구성형, 태그 번호, 값, 다음 위치) — 높은 태그 번호·긴 길이 형식 포함."""
    first = b[i]
    cls, cons, tag, i = first >> 6, bool(first & 0x20), first & 0x1F, i + 1
    if tag == 0x1F:
        tag = 0
        while True:
            tag, more, i = (tag << 7) | (b[i] & 0x7F), b[i] & 0x80, i + 1
            if not more:
                break
    ln = b[i]
    i += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln, i = int.from_bytes(b[i:i + k], "big"), i + k
    if i + ln > len(b):
        raise FidoError("attestation_cert", "DER 길이 오류")
    return cls, cons, tag, b[i:i + ln], i + ln


def _children(v: bytes) -> list[tuple[int, bool, int, bytes]]:
    out, i = [], 0
    while i < len(v):
        cls, cons, tag, val, i = _tlv(v, i)
        out.append((cls, cons, tag, val))
    return out


def _authz(seq: bytes) -> dict[int, bytes]:
    """AuthorizationList — 문맥 태그 번호 → EXPLICIT 안쪽 값(TLV 하나)."""
    return {tag: val for cls, _, tag, val in _children(seq) if cls == 2}


def _android_key(st: dict, leaf: x509.Certificate, auth_data: bytes, cdh: bytes) -> None:
    """WebAuthn §8.4 — 서명 · 증명서 공개키 = 자격 증명 키 · KeyDescription.attestationChallenge = clientDataHash ·
    allApplications 없음 · TEE 강제 목록의 origin = 생성(0) · purpose 에 서명(2)."""
    _sig(leaf.public_key(), st.get("alg"), st.get("sig") or b"", auth_data + cdh)
    if _numbers(leaf.public_key()) != _numbers(_cred_key(auth_data)):
        raise FidoError("attestation_key", "증명서 공개키 ≠ 자격 증명 공개키")
    try:
        raw = leaf.extensions.get_extension_for_oid(KEY_DESCRIPTION).value.value
        kd = _children(_tlv(raw, 0)[3])
        challenge, sw, tee = kd[4][3], kd[6][3], kd[7][3]
    except (x509.ExtensionNotFound, IndexError, ValueError) as e:
        raise FidoError("attestation_cert", "Android KeyDescription 확장 없음·형식 오류") from e
    if challenge != cdh:
        raise FidoError("attestation_challenge", "KeyDescription 의 challenge ≠ clientDataHash")
    sw_l, tee_l = _authz(sw), _authz(tee)
    if 600 in sw_l or 600 in tee_l:
        raise FidoError("attestation_cert", "allApplications — 모든 앱이 쓰는 키")
    origin = _children(tee_l[702])[0][3] if 702 in tee_l else None
    purposes = {int.from_bytes(v, "big") for _, _, _, v in _children(_children(tee_l[1])[0][3])} if 1 in tee_l else set()
    if origin != b"\x00" or 2 not in purposes:
        raise FidoError("attestation_cert", "TEE 생성·서명 용도 키가 아니다(origin·purpose)")


# ── TPM 2.0 (Windows Hello 등) ────────────────────────────────────
def _b2(b: bytes, i: int) -> tuple[bytes, int]:
    n = int.from_bytes(b[i:i + 2], "big")
    return b[i + 2:i + 2 + n], i + 2 + n


def _pub_area(b: bytes) -> tuple[int, int, object]:
    """TPMT_PUBLIC → (type, nameAlg, 공개키)."""
    typ, name_alg = int.from_bytes(b[0:2], "big"), int.from_bytes(b[2:4], "big")
    _, i = _b2(b, 8)                                                   # authPolicy (objectAttributes 4바이트 뒤)
    if typ == 0x0001:                                                  # RSA: symmetric·scheme·keyBits·exponent, unique = n
        exp = int.from_bytes(b[i + 6:i + 10], "big") or 65537
        n, _ = _b2(b, i + 10)
        return typ, name_alg, rsa.RSAPublicNumbers(exp, int.from_bytes(n, "big")).public_key()
    if typ == 0x0023:                                                  # ECC: symmetric·scheme·curveID·kdf, unique = x·y
        if int.from_bytes(b[i + 4:i + 6], "big") != 0x0003:
            raise FidoError("attestation_key", "TPM ECC 곡선은 P-256 만")
        x, j = _b2(b, i + 8)
        y, _ = _b2(b, j)
        return typ, name_alg, ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    raise FidoError("attestation_key", f"TPM 키 종류 {typ:#06x} 지원 안 함")


def _tpm(st: dict, leaf: x509.Certificate, auth_data: bytes, cdh: bytes) -> None:
    """WebAuthn §8.3 — pubArea 키 = 자격 증명 키 · certInfo(magic·type·extraData = H(authData‖cdh)·name = H(pubArea)) ·
    AIK 서명 · AIK 증명서(v3·주체 비움·SAN·EKU tcg-kp-AIKCertificate·CA 아님)."""
    if st.get("ver") != "2.0":
        raise FidoError("attestation_format", "TPM 증명 ver ≠ 2.0")
    pa, ci, alg = st.get("pubArea") or b"", st.get("certInfo") or b"", st.get("alg")
    try:
        _, name_alg, key = _pub_area(pa)
        if ci[0:4] != b"\xffTCG" or ci[4:6] != b"\x80\x17":
            raise FidoError("attestation_cert", "TPM certInfo magic·type 오류")
        _, i = _b2(ci, 6)                                              # qualifiedSigner
        extra, i = _b2(ci, i)
        name, _ = _b2(ci, i + 17 + 8)                                  # clockInfo 17 · firmwareVersion 8 뒤 attested.name
    except (IndexError, ValueError) as e:
        raise FidoError("attestation_cert", "TPM 구조 형식 오류") from e
    if _numbers(key) != _numbers(_cred_key(auth_data)):
        raise FidoError("attestation_key", "TPM pubArea 키 ≠ 자격 증명 공개키")
    if alg not in _HASH or name_alg not in TPM_HASH:
        raise FidoError("attestation_alg", f"TPM 해시 알고리즘 {alg}·{name_alg:#06x} 지원 안 함")
    h = hashes.Hash(_HASH[alg]())
    h.update(auth_data + cdh)
    if extra != h.finalize():
        raise FidoError("attestation_challenge", "TPM certInfo.extraData ≠ H(authData‖clientDataHash)")
    h = hashes.Hash(TPM_HASH[name_alg]())
    h.update(pa)
    if name != name_alg.to_bytes(2, "big") + h.finalize():
        raise FidoError("attestation_cert", "TPM certInfo.attested.name ≠ pubArea 이름")
    _sig(leaf.public_key(), alg, st.get("sig") or b"", ci)
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound as e:
        raise FidoError("attestation_cert", "AIK 증명서에 EKU·SAN 없음") from e
    if leaf.version != x509.Version.v3 or len(leaf.subject) or TCG_AIK not in eku or _is_ca(leaf):
        raise FidoError("attestation_cert", "AIK 증명서 요건 불충족(v3·주체 비움·tcg-kp-AIKCertificate·CA 아님)")


def verify_cli(d: str, crl: bool = False) -> int:
    t = time.time()
    m = read_dir(d)
    out = {"ok": True, "no": m.no, "nextUpdate": m.next_update, "entries": len(m.entries), "signer": m.signer,
           "flagged": sum(1 for a in m.entries if m.problem(a)), "sha256": m.meta.get("sha256"), "sec": round(time.time() - t, 2)}
    if crl:
        out["crl"] = crl_check(d)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        try:
            sys.exit(verify_cli(sys.argv[2], "--crl" in sys.argv[3:]))
        except FidoError as exc:
            print(json.dumps({"ok": False, "reason": exc.reason, "error": str(exc)}, ensure_ascii=False))
            sys.exit(1)
    print("usage: python -m app.fido verify DIR [--crl]", file=sys.stderr)
    sys.exit(2)
