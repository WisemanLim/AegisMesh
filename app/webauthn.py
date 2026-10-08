"""WebAuthn(패스키·보안 키) 등록·인증 검증 (SCR-B02 2단계 인증, FR-D5-01) — W3C WebAuthn L2 의 RP 검증 절차.

외부 라이브러리 없이 `cryptography` 로 구현한다: CBOR(필요한 부분집합) → authenticatorData → COSE 공개키 → 서명 검증.
증명(attestation)은 기본 'none'(소유 증명이 목적). 테넌트가 AAGUID 허용목록을 두면 'direct' 로 받아 app.fido 가 제조사 체인·MDS 로 확인한다(Epic 54).
검사: 유형(create/get) · challenge(서버 발급·1회) · origin(허용 목록) · rpIdHash · UP(사용자 존재) · UV(사용자 확인) · 서명 · 서명 카운터 역행(복제 의심).
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGS = {-7: "ES256", -8: "EdDSA", -257: "RS256"}
UP, UV, AT = 0x01, 0x04, 0x40


class WebAuthnError(Exception):
    pass


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > 65536:
        raise WebAuthnError("base64url 값이 아니다")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError as exc:
        raise WebAuthnError("base64url 디코딩 실패") from exc


# ── CBOR (RFC 8949) — WebAuthn 이 쓰는 부분집합: 정수·바이트·문자열·배열·맵·태그·단순값(정해진 길이만) ──
def _cbor(b: bytes, i: int, depth: int = 0):
    if depth > 16 or i >= len(b):
        raise WebAuthnError("CBOR 형식 오류")
    major, info = b[i] >> 5, b[i] & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if i + n > len(b):
            raise WebAuthnError("CBOR 길이 초과")
        arg = int.from_bytes(b[i:i + n], "big")
        if major == 7 and info in (25, 26, 27):                       # 부동소수
            v = struct.unpack({25: ">e", 26: ">f", 27: ">d"}[info], b[i:i + n])[0]
            return v, i + n
        i += n
    else:
        raise WebAuthnError("CBOR 무한 길이 미지원")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(b):
            raise WebAuthnError("CBOR 길이 초과")
        raw = b[i:i + arg]
        return (raw if major == 2 else raw.decode()), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = _cbor(b, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        m = {}
        for _ in range(arg):
            k, i = _cbor(b, i, depth + 1)
            v, i = _cbor(b, i, depth + 1)
            m[k] = v
        return m, i
    if major == 6:
        return _cbor(b, i, depth + 1)
    if major == 7:
        return {20: False, 21: True, 22: None}.get(arg), i
    raise WebAuthnError("CBOR 형식 오류")


def cbor_loads(b: bytes):
    v, _ = _cbor(b, 0)
    return v


def cbor_prefix(b: bytes):
    """앞의 CBOR 항목 하나와 그 길이 — authData 안의 공개키는 뒤에 확장이 붙을 수 있다."""
    return _cbor(b, 0)


# ── COSE 공개키 ───────────────────────────────────────────────
def public_key(cose: dict):
    kty, alg = cose.get(1), cose.get(3)
    if alg not in ALGS:
        raise WebAuthnError(f"지원하지 않는 서명 알고리즘 {alg}")
    if kty == 2 and alg == -7 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise WebAuthnError("EC2 키 형식 오류")
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    if kty == 1 and alg == -8 and cose.get(-1) == 6:
        return ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
    if kty == 3 and alg == -257:
        n, e = int.from_bytes(cose[-1], "big"), int.from_bytes(cose[-2], "big")
        if n.bit_length() < 2048:
            raise WebAuthnError("RSA 키 2048비트 미만")
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise WebAuthnError("COSE 키 형식 오류")


def _verify(cose: dict, sig: bytes, data: bytes) -> None:
    key = public_key(cose)
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))          # WebAuthn ES256 서명은 ASN.1 DER
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, data)
        else:
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise WebAuthnError("서명 검증 실패") from exc


def _auth_data(ad: bytes, rp_id: str, require_uv: bool) -> dict:
    if len(ad) < 37:
        raise WebAuthnError("authenticatorData 짧음")
    if ad[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("rpIdHash 불일치 — 다른 사이트용 자격증명")
    flags = ad[32]
    if not flags & UP:
        raise WebAuthnError("사용자 존재(UP) 확인 없음")
    if require_uv and not flags & UV:
        raise WebAuthnError("사용자 확인(UV — PIN·생체) 없음")
    out = {"flags": flags, "signCount": int.from_bytes(ad[33:37], "big")}
    if flags & AT:
        if len(ad) < 55:
            raise WebAuthnError("attestedCredentialData 짧음")
        n = int.from_bytes(ad[53:55], "big")
        cid = ad[55:55 + n]
        if len(cid) != n or n > 1023:
            raise WebAuthnError("자격증명 ID 길이 오류")
        cose, used = cbor_prefix(ad[55 + n:])
        out |= {"aaguid": ad[37:53].hex(), "credentialId": cid, "cose": cose, "coseBytes": ad[55 + n:55 + n + used]}
    return out


def _client_data(raw_b64: str, kind: str, challenge: str, origins: list[str]) -> bytes:
    raw = unb64u(raw_b64)
    try:
        cd = json.loads(raw)
    except ValueError as exc:
        raise WebAuthnError("clientDataJSON 형식 오류") from exc
    if cd.get("type") != kind:
        raise WebAuthnError(f"clientData.type ≠ {kind}")
    if cd.get("challenge") != challenge:
        raise WebAuthnError("challenge 불일치 — 재사용·위조 의심")
    if cd.get("origin") not in origins:
        raise WebAuthnError(f"origin 불일치 {cd.get('origin')!r}")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("교차 출처 iframe 인증 거부")
    return raw


def verify_registration(cred: dict, challenge: str, rp_id: str, origins: list[str], require_uv: bool = True) -> dict:
    if cred.get("type") != "public-key":
        raise WebAuthnError("type ≠ public-key")
    r = cred.get("response") or {}
    raw_cd = _client_data(r.get("clientDataJSON", ""), "webauthn.create", challenge, origins)
    att = cbor_loads(unb64u(r.get("attestationObject", "")))
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise WebAuthnError("attestationObject 형식 오류")
    ad = _auth_data(att["authData"], rp_id, require_uv)
    if "credentialId" not in ad:
        raise WebAuthnError("자격증명 데이터(AT) 없음")
    if b64u(ad["credentialId"]) != cred.get("rawId", cred.get("id")):
        raise WebAuthnError("rawId ≠ authData 자격증명 ID")
    public_key(ad["cose"])                                              # 지원 알고리즘·키 형식 확인
    return {"credentialId": b64u(ad["credentialId"]), "publicKey": b64u(ad["coseBytes"]), "signCount": ad["signCount"],
            "aaguid": ad["aaguid"], "alg": ALGS[ad["cose"][3]], "fmt": att.get("fmt"),
            "transports": [t for t in (r.get("transports") or []) if isinstance(t, str)][:8],
            "attestation": {"att": att, "authData": att["authData"], "clientDataHash": hashlib.sha256(raw_cd).digest()}}


def verify_assertion(cred: dict, challenge: str, rp_id: str, origins: list[str], public_key_b64: str, sign_count: int,
                     require_uv: bool = True) -> int:
    """성공 시 새 서명 카운터. 카운터가 0 이 아닌데 늘지 않으면 복제 인증기 의심으로 거부."""
    if cred.get("type") != "public-key":
        raise WebAuthnError("type ≠ public-key")
    r = cred.get("response") or {}
    raw_cd = _client_data(r.get("clientDataJSON", ""), "webauthn.get", challenge, origins)
    ad_raw = unb64u(r.get("authenticatorData", ""))
    ad = _auth_data(ad_raw, rp_id, require_uv)
    _verify(cbor_loads(unb64u(public_key_b64)), unb64u(r.get("signature", "")), ad_raw + hashlib.sha256(raw_cd).digest())
    new = ad["signCount"]
    if (new or sign_count) and new <= sign_count:
        raise WebAuthnError(f"서명 카운터 역행({sign_count} → {new}) — 인증기 복제 의심")
    return new
