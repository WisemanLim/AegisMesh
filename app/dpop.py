"""DPoP 소유 증명 (RFC 9449) — 세션 토큰을 클라이언트 키에 묶는다 (SCR-B02 · FR-D5-03).

로그인 요청에 DPoP 증명이 있으면 세션에 키 지문(jkt, RFC 7638)을 기록하고, 그 뒤 모든 요청은 같은 키로 서명한
새 증명(htm·htu·iat·jti·ath)을 함께 보내야 한다. 증명 없이 토큰만 쓰면(= 탈취 토큰 재사용) 사용자 세션 전체를 폐기한다.
콘솔은 웹 서버가 세션마다 P-256 키를 만들어 봉인 쿠키로 들고 다니며 API 호출마다 증명을 만든다(브라우저 JS 는 키·토큰을 못 본다).
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SKEW_SEC = 60                  # iat 허용 오차(초) — 이 안에서만 jti 재사용을 기억하면 된다


class DpopError(Exception):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code, self.msg = code, msg              # code: invalid(형식·서명) · stale(시각) · mismatch(요청 불일치)


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def thumbprint(jwk: dict) -> str:
    """RFC 7638 — 필수 멤버만 사전순·공백 없이 JSON → SHA-256 → base64url."""
    if jwk.get("kty") == "EC":
        req = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif jwk.get("kty") == "OKP":
        req = {k: jwk[k] for k in ("crv", "kty", "x")}
    else:
        raise DpopError("invalid", "DPoP 키 형식(EC P-256·OKP Ed25519)만")
    return _b64e(hashlib.sha256(json.dumps(req, separators=(",", ":"), sort_keys=True).encode()).digest())


def ath(token: str) -> str:
    return _b64e(hashlib.sha256(token.encode()).digest())


def verify(proof: str, method: str, url_path: str, access_token: str | None = None, now: float | None = None) -> dict:
    """증명 검증 → {jkt, jti, iat}. htu 는 경로만 비교한다(프록시·컨테이너 내부 주소로 호스트가 달라질 수 있음)."""
    try:
        h64, p64, s64 = proof.split(".")
        head, pay, sig = json.loads(_b64d(h64)), json.loads(_b64d(p64)), _b64d(s64)
    except (ValueError, TypeError) as exc:
        raise DpopError("invalid", "DPoP 증명 형식 오류") from exc
    if not isinstance(head, dict) or not isinstance(pay, dict):
        raise DpopError("invalid", "DPoP 증명 형식 오류")
    jwk = head.get("jwk")
    if head.get("typ") != "dpop+jwt" or head.get("alg") not in ("ES256", "EdDSA") or not isinstance(jwk, dict):
        raise DpopError("invalid", "DPoP 헤더(typ·alg·jwk) 오류")
    if "d" in jwk:
        raise DpopError("invalid", "DPoP jwk 에 개인키가 들어 있다")
    data = f"{h64}.{p64}".encode()
    try:
        if head["alg"] == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256" and len(sig) == 64:
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"),
                                                ec.SECP256R1()).public_key()
            key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), data, ec.ECDSA(hashes.SHA256()))
        elif head["alg"] == "EdDSA" and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(_b64d(jwk["x"])).verify(sig, data)
        else:
            raise DpopError("invalid", "DPoP alg·키 조합 오류")
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise DpopError("invalid", "DPoP 서명 검증 실패") from exc
    now = time.time() if now is None else now
    iat, jti = pay.get("iat"), pay.get("jti")
    if not isinstance(iat, (int, float)) or abs(now - iat) > SKEW_SEC:
        raise DpopError("stale", f"DPoP iat 가 허용 오차 {SKEW_SEC}초 밖 — 시계 확인")
    if not isinstance(jti, str) or not 8 <= len(jti) <= 64:
        raise DpopError("invalid", "DPoP jti 오류")
    if str(pay.get("htm", "")).upper() != method.upper() or unquote(urlsplit(str(pay.get("htu", ""))).path) != unquote(url_path):
        raise DpopError("mismatch", "DPoP htm·htu 가 요청과 다르다")
    if access_token is not None and pay.get("ath") != ath(access_token):
        raise DpopError("mismatch", "DPoP ath 가 토큰과 다르다")
    return {"jkt": thumbprint(jwk), "jti": jti, "iat": iat}
