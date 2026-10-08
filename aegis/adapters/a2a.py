"""A2A 어댑터 (PRD §12.4, FR-X01) — 에이전트 하나를 Agent2Agent v1.0 에이전트로 노출. 플랫폼 의존 없음.

  aegis serve <agent> --protocol a2a [--port 8080] [--key k] [--public-url URL] [--trust-jwks URL|file]

- 서명 AgentCard: GET /.well-known/agent-card.json — 카드에서 signatures 를 뺀 정규 JSON(키 정렬·공백 없음, RFC 8785 와 같은
  결과 — 카드에 실수 값 없음)을 분리형 JWS(EdDSA)로 서명. 공개키는 GET /.well-known/jwks.json (protected 헤더의 jku·kid).
- JSON-RPC 2.0 (protocolBinding JSONRPC, A2A-Version: 1.0): SendMessage · GetTask · CancelTask.
  판정은 즉시 끝나므로 Task 는 TASK_STATE_COMPLETED, Finding 은 artifact(data part). 입력 원문은 보존하지 않는다(history 비움, NFR-D1).
- 호출자 인증(선택, FR-X01 상호 인증): --trust-jwks 를 주면 Authorization: Bearer <JWT-SVID>(EdDSA) 의 서명·만료·aud 를 검증.
  폐기 조회는 플랫폼 밖이라 하지 않는다 — SVID 수명(1시간)이 상한.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.request
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aegis.ledger_verify import canonical, key_id_of
from aegis.schemas import JudgeRequest

PROTOCOL_VERSION = "1.0"
CARD_PATH = "/.well-known/agent-card.json"
JWKS_PATH = "/.well-known/jwks.json"
RPC_PATH = "/a2a"
ERR = {"parse": (-32700, "JSON parse error"), "request": (-32600, "Invalid Request"), "method": (-32601, "Method not found"),
       "params": (-32602, "Invalid params"), "internal": (-32603, "Internal error"),
       "task": (-32001, "TaskNotFoundError"), "cancel": (-32002, "TaskNotCancelableError"),
       "unsupported": (-32004, "UnsupportedOperationError"), "content": (-32005, "ContentTypeNotSupportedError"),
       "version": (-32009, "VersionNotSupportedError")}
FIELD = {"input": "text", "output": "output"}                 # 텍스트 part → 관문별 요청 필드


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def raw_pub(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> dict:
    raw = raw_pub(key)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw), "kid": key_id_of(raw), "use": "sig", "alg": "EdDSA"}


def keys_from_jwks(jwks: dict) -> dict[str, Ed25519PublicKey]:
    return {k["kid"]: Ed25519PublicKey.from_public_bytes(unb64u(k["x"]))
            for k in jwks.get("keys", []) if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("kid")}


def load_key(path: str | None) -> Ed25519PrivateKey:
    """aegis keygen 출력(base64 32바이트) — 없으면 임시 키(재기동 시 바뀜)."""
    if not path:
        return Ed25519PrivateKey.generate()
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(path).read_text().strip()))


# ── AgentCard 서명·검증 ──────────────────────────────────────
def sign_card(card: dict, key: Ed25519PrivateKey, jku: str | None = None) -> dict:
    unsigned = {k: v for k, v in card.items() if k != "signatures"}
    head = {"alg": "EdDSA", "typ": "JOSE", "kid": key_id_of(raw_pub(key))} | ({"jku": jku} if jku else {})
    protected = b64u(json.dumps(head, separators=(",", ":")).encode())
    sig = key.sign(f"{protected}.{b64u(canonical(unsigned))}".encode())
    return unsigned | {"signatures": [{"protected": protected, "signature": b64u(sig)}]}


def verify_card(card: dict, trusted: dict[str, Ed25519PublicKey]) -> dict:
    """{ok, kid, detail} — 서명 하나라도 신뢰 키로 검증되면 ok. 신뢰 키에 없는 kid 는 untrusted."""
    sigs = card.get("signatures") or []
    if not sigs:
        return {"ok": False, "kid": None, "reason": "unsigned", "detail": "AgentCard 서명 없음"}
    unsigned = canonical({k: v for k, v in card.items() if k != "signatures"})
    last = {"ok": False, "kid": None, "reason": "untrusted", "detail": "신뢰 키 없음"}
    for s in sigs:
        try:
            head = json.loads(unb64u(s["protected"]))
        except (KeyError, ValueError):
            return {"ok": False, "kid": None, "reason": "malformed", "detail": "protected 헤더 형식 오류"}
        kid = head.get("kid")
        if head.get("alg") != "EdDSA":
            last = {"ok": False, "kid": kid, "reason": "alg", "detail": f"지원하지 않는 알고리즘 {head.get('alg')}"}
            continue
        if kid not in trusted:
            last = {"ok": False, "kid": kid, "reason": "untrusted", "detail": f"신뢰 저장소에 없는 서명키 {kid}"}
            continue
        try:
            trusted[kid].verify(unb64u(s["signature"]), f"{s['protected']}.{b64u(unsigned)}".encode())
            return {"ok": True, "kid": kid, "reason": "ok", "detail": f"AgentCard 서명 유효 (kid {kid})", "jku": head.get("jku")}
        except (InvalidSignature, ValueError, KeyError):
            return {"ok": False, "kid": kid, "reason": "bad-signature", "detail": "AgentCard 서명 검증 실패(변조)"}
    return last


def build_card(agent, public_url: str, secured: bool = False) -> dict:
    m, spec = agent.manifest.metadata, agent.manifest.spec
    gate = spec.gate
    ex = {"input": ['{"text": "사용자 입력"}'], "output": ['{"output": "모델 출력"}'],
          "tool": ['{"tool": {"name": "transfer", "args": {"amount": 500000}}}']}.get(gate, ['{"artifact": {...}}'])
    card = {
        "name": f"AegisMesh {m.id} {m.name}", "description": f"{m.name_ko} — {gate} 관문 판정 에이전트 (AegisMesh). 판정은 Finding JSON 아티팩트로 돌려준다.",
        "supportedInterfaces": [{"url": public_url.rstrip("/") + RPC_PATH, "protocolBinding": "JSONRPC", "protocolVersion": PROTOCOL_VERSION}],
        "provider": {"organization": "AegisMesh", "url": public_url.rstrip("/")},
        "version": m.version,
        "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
        "defaultInputModes": ["application/json", "text/plain"], "defaultOutputModes": ["application/json"],
        "skills": [{"id": "judge", "name": f"{m.id} 판정", "description": f"{m.source.item} ({m.source.domain}) 위험 판정 — JudgeRequest(data part) 또는 텍스트(text part)",
                    "tags": [gate, m.source.domain, "aegismesh"], "examples": ex,
                    "inputModes": ["application/json", "text/plain"], "outputModes": ["application/json"]}],
    }
    if secured:
        card["securitySchemes"] = {"svid": {"httpAuthSecurityScheme": {"scheme": "Bearer", "bearerFormat": "JWT-SVID (EdDSA)",
                                                                        "description": "AegisMesh 워크로드 신원"}}}
    return card


# ── 호출자 JWT-SVID 검증 ─────────────────────────────────────
class AuthError(Exception):
    pass


def verify_svid(token: str, keys: dict[str, Ed25519PublicKey], audience: str) -> dict:
    try:
        hb, bb, sb = token.split(".")
        head, claims = json.loads(unb64u(hb)), json.loads(unb64u(bb))
    except ValueError as exc:
        raise AuthError("JWT-SVID 형식 오류") from exc
    if head.get("alg") != "EdDSA" or head.get("kid") not in keys:
        raise AuthError("알 수 없는 서명 키")
    try:
        keys[head["kid"]].verify(unb64u(sb), f"{hb}.{bb}".encode())
    except InvalidSignature as exc:
        raise AuthError("JWT-SVID 서명 불일치") from exc
    if claims.get("exp", 0) <= time.time():
        raise AuthError("JWT-SVID 만료")
    aud = claims.get("aud") or []
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise AuthError(f"대상(aud) 불일치 — {audience} 필요")
    if not str(claims.get("sub", "")).startswith("spiffe://"):
        raise AuthError("SPIFFE ID 아님")
    return claims


def fetch_json(src: str, headers: dict | None = None, body: dict | None = None, timeout: float = 5) -> Any:
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Accept": "application/json", **({"Content-Type": "application/json"} if body is not None else {}),
                                              **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    return json.loads(Path(src).read_text())


# ── 서버 ─────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_request(agent, message: dict) -> tuple[dict, str | None]:
    """A2A Message → JudgeRequest dict. data part 는 요청 필드로 합치고, text part 는 관문 필드(text|output)로."""
    data: dict = {}
    texts = []
    for p in message.get("parts") or []:
        if "data" in p:
            if not isinstance(p["data"], dict):
                raise ValueError("data part 는 JSON 객체(JudgeRequest)")
            data |= p["data"]
        elif "text" in p:
            texts.append(str(p["text"]))
        else:
            return {}, "content"
    if texts:
        data.setdefault(FIELD.get(agent.manifest.spec.gate, "text"), "\n".join(texts))
    if not data:
        raise ValueError("parts 가 비어 있다")
    return data, None


def create_app(agent, key: Ed25519PrivateKey | None = None, public_url: str = "http://localhost:8080",
               trust_jwks: str | None = None, audience: str = "aegismesh", max_tasks: int = 1000):
    key = key or Ed25519PrivateKey.generate()
    base = public_url.rstrip("/")
    card = sign_card(build_card(agent, base, secured=bool(trust_jwks)), key, base + JWKS_PATH)
    jwks = {"keys": [jwk(key)]}
    caller_keys = keys_from_jwks(fetch_json(trust_jwks)) if trust_jwks else None
    tasks: OrderedDict[str, dict] = OrderedDict()
    app = FastAPI(title=f"aegis a2a {agent.id}", version=agent.manifest.metadata.version)

    def rpc_error(rid, kind: str, detail: str | None = None, status: int = 200):
        code, msg = ERR[kind]
        err = {"code": code, "message": msg} | ({"data": {"detail": detail}} if detail else {})
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": err}, status_code=status)

    @app.get(CARD_PATH)
    def agent_card():
        return JSONResponse(card, headers={"Cache-Control": "public, max-age=300"})

    @app.get(JWKS_PATH)
    def keys():
        return jwks

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "agent": agent.id, "protocol": "a2a", "protocolVersion": PROTOCOL_VERSION}

    @app.post(RPC_PATH)
    async def rpc(request: Request):
        try:
            body = await request.json()
        except ValueError:
            return rpc_error(None, "parse")
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
            return rpc_error(body.get("id") if isinstance(body, dict) else None, "request", "JSON-RPC 2.0 단건 요청만")
        rid, method, params = body.get("id"), body["method"], body.get("params") or {}
        ver = request.headers.get("A2A-Version") or request.query_params.get("A2A-Version") or ""
        if ver != PROTOCOL_VERSION:
            return rpc_error(rid, "version", f"A2A-Version {ver or '(없음=0.3)'} 미지원 — {PROTOCOL_VERSION} 만")
        if caller_keys is not None:
            scheme, _, tok = request.headers.get("authorization", "").partition(" ")
            try:
                if scheme.lower() != "bearer" or not tok:
                    raise AuthError("Authorization: Bearer <JWT-SVID> 필요")
                verify_svid(tok, caller_keys, audience)
            except AuthError as exc:
                r = rpc_error(rid, "request", f"인증 실패: {exc}", 401)
                r.headers["WWW-Authenticate"] = 'Bearer realm="a2a"'
                return r
        if method == "SendMessage":
            msg = params.get("message")
            if not isinstance(msg, dict) or not msg.get("messageId"):
                return rpc_error(rid, "params", "message.messageId 필요")
            try:
                data, bad = to_request(agent, msg)
                if bad:
                    return rpc_error(rid, "content", "text·data part 만 지원 (파일·바이너리 미지원)")
                req = JudgeRequest.model_validate(data)
            except ValueError as exc:
                return rpc_error(rid, "params", str(exc)[:300])
            f = agent.judge(req, (msg.get("metadata") or {}).get("engine"))
            ctx = msg.get("contextId") or str(uuid.uuid4())
            task = {"id": str(uuid.uuid4()), "contextId": ctx,
                    "status": {"state": "TASK_STATE_COMPLETED", "timestamp": _now(),
                               "message": {"messageId": str(uuid.uuid4()), "contextId": ctx, "role": "ROLE_AGENT",
                                           "parts": [{"text": f"{f.verdict} · {f.rule_id} · 신뢰도 {f.confidence}"}]}},
                    "artifacts": [{"artifactId": str(uuid.uuid4()), "name": "finding", "description": "AegisMesh Finding/v1",
                                   "parts": [{"data": f.dump(), "mediaType": "application/json"}]}],
                    "history": [],                                   # 입력 원문 미보존 (NFR-D1)
                    "metadata": {"agent": agent.id, "verdict": f.verdict, "traceId": f.trace_id}}
            tasks[task["id"]] = task
            while len(tasks) > max_tasks:
                tasks.popitem(last=False)
            return {"jsonrpc": "2.0", "id": rid, "result": {"task": task}}
        if method == "GetTask":
            t = tasks.get(str(params.get("id", "")))
            return {"jsonrpc": "2.0", "id": rid, "result": t} if t else rpc_error(rid, "task", f"task {params.get('id')} 없음")
        if method == "CancelTask":
            if str(params.get("id", "")) not in tasks:
                return rpc_error(rid, "task", f"task {params.get('id')} 없음")
            return rpc_error(rid, "cancel", "판정 태스크는 즉시 완료 — 취소할 수 없다")
        if method in ("SendStreamingMessage", "SubscribeToTask", "ListTasks", "CreateTaskPushNotificationConfig",
                      "GetTaskPushNotificationConfig", "ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig",
                      "GetExtendedAgentCard"):
            return rpc_error(rid, "unsupported", f"{method} 미지원 (capabilities 참고)")
        return rpc_error(rid, "method", f"{method} — v1.0 메서드 이름(SendMessage 등)을 쓴다")

    return app


# ── 클라이언트 (aegis a2a card|send) ─────────────────────────
def trusted_keys(trust: str | None, card: dict) -> tuple[dict[str, Ed25519PublicKey], str]:
    """신뢰 고정: --trust(JWKS URL·파일) 우선. 없으면 카드의 jku — 자기 주장(TOFU)이라 신뢰 고정이 아님을 표시."""
    if trust:
        return keys_from_jwks(fetch_json(trust)), "pinned"
    for s in card.get("signatures") or []:
        try:
            jku = json.loads(unb64u(s["protected"])).get("jku")
        except (KeyError, ValueError):
            continue
        if jku:
            return keys_from_jwks(fetch_json(jku)), "self-asserted"
    return {}, "none"


def card_url(url: str) -> str:
    return url if url.endswith(".json") else url.rstrip("/") + CARD_PATH


def send(url: str, request: dict, trust: str | None = None, token: str | None = None, allow_unpinned: bool = False) -> dict:
    card = fetch_json(card_url(url))
    keys, how = trusted_keys(trust, card)
    v = verify_card(card, keys)
    if not v["ok"]:
        raise RuntimeError(f"AgentCard 검증 실패 — {v['detail']} (호출 거부, FR-X01)")
    if how != "pinned" and not allow_unpinned:
        raise RuntimeError("신뢰 고정(--trust JWKS) 없이 카드 자체 jku 만 확인됨 — 호출 거부 (--allow-unpinned 로 무시)")
    iface = next((i for i in card.get("supportedInterfaces", []) if i.get("protocolBinding") == "JSONRPC"), None)
    if not iface or iface.get("protocolVersion") != PROTOCOL_VERSION:
        raise RuntimeError(f"JSONRPC {PROTOCOL_VERSION} 인터페이스 없음")
    parts = [{"data": request}] if not isinstance(request, str) else [{"text": request}]
    msg = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": parts}
    out = fetch_json(iface["url"], headers={"A2A-Version": PROTOCOL_VERSION} | ({"Authorization": f"Bearer {token}"} if token else {}),
                     body={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": msg}})
    return {"card": {"name": card["name"], "version": card["version"], "kid": v["kid"], "trust": how}, "response": out}
