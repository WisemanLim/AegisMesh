"""SPIRE 연동 (Epic 53 · FR-P07 · 화면설계서 "워크로드 신원 — SPIRE") — IDENTITY_BACKEND=spire 일 때 app.identity 가 쓴다.

- 등록: AegisMesh 워크로드 신원(spiffe_id) → SPIRE 등록 항목. 부모 = 노드 별칭(SPIRE_NODE_ID, make spire-up 이 join token 으로 만든다),
  선택자 = unix:uid:<이 프로세스 uid>(api·worker 가 같은 uid), JWT 수명 = SVID_TTL_SEC. 폐기된 신원은 항목을 지운다. 관리 소켓 + spire-server CLI.
- 발급: Workload API(spire-agent CLI) — api 와 PID 네임스페이스를 함께 쓰는 에이전트가 프로세스 uid 를 증명하고, 키·서명·회전은 SPIRE 몫.
- 검증: SPIRE JWT 번들(ES256 공개키, kid)로 서명 확인. 번들은 관리 소켓에서 받아 잠시 캐시한다.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app.core.config import settings

_bundle: dict = {"at": 0.0, "keys": {}}


class SpireError(Exception):
    pass


def enabled() -> bool:
    return settings.identity_backend == "spire"


def node_id() -> str:
    return settings.spire_node_id or f"spiffe://{settings.spiffe_trust_domain}/node/api"


def _run(args: list[str]):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SpireError(f"SPIRE 호출 실패 — {e}") from e
    if r.returncode != 0:
        raise SpireError(f"SPIRE {args[1]} {args[2]} 실패 — {(r.stderr or r.stdout).strip()[:200]}")
    return json.loads(r.stdout) if r.stdout.strip().startswith(("{", "[")) else r.stdout


def _server(*args: str):
    return _run(["spire-server", *args, "-socketPath", settings.spire_server_socket])


def _sid(d: dict) -> str:
    return f"spiffe://{d['trust_domain']}{d['path']}"


def entries() -> dict[str, dict]:
    """노드 별칭 아래 등록 항목 — spiffe_id → {id, ttl, selectors}."""
    out = {}
    for e in (_server("entry", "show", "-parentID", node_id(), "-output", "json") or {}).get("entries") or []:
        out[_sid(e["spiffe_id"])] = {"id": e["id"], "ttl": e.get("jwt_svid_ttl", 0), "selectors": [f"{s['type']}:{s['value']}" for s in e["selectors"]]}
    return out


def ensure(active: dict[str, int], revoked: set[str]) -> dict:
    """active = {spiffe_id: jwt ttl}. 없거나 설정이 다르면 만들고(다르면 지우고 다시), 폐기된 신원은 지운다."""
    cur, sel = entries(), f"unix:uid:{os.getuid()}"
    made = dropped = 0
    for sid, e in cur.items():
        if sid in revoked or (sid in active and (e["ttl"] != active[sid] or e["selectors"] != [sel])):
            _server("entry", "delete", "-entryID", e["id"])
            dropped += 1
    cur = {k: v for k, v in cur.items() if k not in revoked and not (k in active and (v["ttl"] != active[k] or v["selectors"] != [sel]))}
    for sid, ttl in active.items():
        if sid not in cur:
            _server("entry", "create", "-parentID", node_id(), "-spiffeID", sid, "-selector", sel, "-jwtSVIDTTL", str(ttl), "-output", "json")
            made += 1
    return {"created": made, "deleted": dropped, "selector": sel, "parent": node_id()}


def fetch_jwt(spiffe_id: str, audience: list[str]) -> str:
    out = _run(["spire-agent", "api", "fetch", "jwt", "-socketPath", settings.spire_agent_socket, "-audience", ",".join(audience),
                "-spiffeID", spiffe_id, "-output", "json"])
    for part in out if isinstance(out, list) else [out]:
        for s in part.get("svids") or []:
            if s.get("spiffe_id") == spiffe_id:
                return s["svid"]
    raise SpireError(f"Workload API 가 {spiffe_id} SVID 를 주지 않음(등록·선택자 확인)")


def jwks(refresh: bool = False) -> dict:
    """SPIRE 신뢰 번들 중 JWT 서명 키 — 잠시 캐시(회전된 키는 다음 새로 고침부터)."""
    if refresh or time.time() - _bundle["at"] > 60 or not _bundle["keys"]:
        b = _server("bundle", "show", "-format", "spiffe")
        _bundle["keys"] = {k["kid"]: k for k in b.get("keys", []) if k.get("use") == "jwt-svid"}
        _bundle["at"] = time.time()
    return {"keys": list(_bundle["keys"].values())}


def _int(s: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")


def verify_signature(head: dict, signing_input: bytes, sig: bytes) -> None:
    """ES256 JWS — kid 로 번들 키를 찾고(없으면 한 번 새로 고침) r‖s 서명을 확인한다."""
    if head.get("alg") != "ES256":
        raise SpireError("알 수 없는 서명 알고리즘")
    key = _bundle["keys"].get(head.get("kid")) if _bundle["keys"] else None
    if key is None:
        jwks(refresh=True)
        key = _bundle["keys"].get(head.get("kid"))
    if key is None:
        raise SpireError("SPIRE 번들에 없는 서명 키")
    pub = ec.EllipticCurvePublicNumbers(_int(key["x"]), _int(key["y"]), ec.SECP256R1()).public_key()
    if len(sig) != 64:
        raise SpireError("ES256 서명 길이 오류")
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signing_input,
                   ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise SpireError("JWT-SVID 서명 불일치") from e


def status() -> dict:
    try:
        es = entries()
        return {"backend": "spire", "ok": True, "parent": node_id(), "entries": len(es), "jwtKeys": len(jwks()["keys"])}
    except SpireError as e:
        return {"backend": "spire", "ok": False, "error": str(e)}
