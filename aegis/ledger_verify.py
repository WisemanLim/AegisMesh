"""증적 묶음 독립 검증기 (PRD §12.6 "감사자가 독립 검증할 수 있어야 한다").

서버·DB 없이 묶음 파일과 이 모듈(hashlib + cryptography)만으로 검증한다.
  python -m aegis verify-bundle bundle.json
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = "0" * 64
BUNDLE_FORMAT = "aegismesh.io/EvidenceBundle/v1"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_hash(prev_hash: str, rec: dict) -> str:
    """rec: id·kind·refId·tenant·body·createdAt. 체인 = sha256(prev_hash ‖ canonical(rec))."""
    core = {k: rec[k] for k in ("id", "kind", "refId", "tenant", "body", "createdAt")}
    return hashlib.sha256(prev_hash.encode() + canonical(core)).hexdigest()


def checkpoint_message(seq: int, hash_: str, key_id: str) -> bytes:
    return canonical({"seq": seq, "hash": hash_, "keyId": key_id})


def key_id_of(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def verify_records(records: list[dict], anchor: str) -> tuple[bool, str]:
    prev = anchor
    for r in records:
        if r["prevHash"] != prev:
            return False, f"seq {r['seq']}: prevHash 불일치 (체인 단절)"
        if record_hash(prev, r) != r["hash"]:
            return False, f"seq {r['seq']}: 해시 불일치 (내용 변조)"
        prev = r["hash"]
    return True, prev


def verify_signature(public_b64: str, cp: dict) -> bool:
    raw = base64.b64decode(public_b64)
    if key_id_of(raw) != cp["keyId"]:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(
            base64.b64decode(cp["signature"]), checkpoint_message(cp["seq"], cp["hash"], cp["keyId"]))
        return True
    except InvalidSignature:
        return False


def verify_bundle(bundle: dict) -> tuple[bool, str]:
    if bundle.get("format") != BUNDLE_FORMAT:
        return False, f"알 수 없는 형식 {bundle.get('format')}"
    recs = bundle["records"]
    if not recs:
        return False, "레코드 없음"
    ok, last = verify_records(recs, bundle["anchor"])
    if not ok:
        return False, last
    cp = bundle["checkpoint"]
    if cp["seq"] != recs[-1]["seq"] or cp["hash"] != last:
        return False, "체크포인트가 마지막 레코드와 다르다"
    if not verify_signature(bundle["publicKey"], cp):
        return False, "체크포인트 서명 검증 실패"
    return True, f"레코드 {len(recs)}건 (seq {recs[0]['seq']}–{recs[-1]['seq']}) 체인·서명 검증 통과, keyId {cp['keyId']}"
