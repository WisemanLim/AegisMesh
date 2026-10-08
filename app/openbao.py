"""OpenBao 시크릿 백엔드 (Epic 41 · FR-P07 · 원본 §1.3 발견 6) — 동적 시크릿 임대를 OpenBao 토큰으로 발급한다.

- 임대 = 토큰 역할 `aegis-lease`(orphan·갱신 가능·explicit_max_ttl = SECRET_LEASE_MAX_SEC)로 만든 서비스 토큰. 범위·테넌트·경로·보유자는 토큰 meta.
- 수명·갱신·회수·만료의 원본은 OpenBao — AegisMesh 는 접근자(accessor)와 시크릿 해시만 둔다(원문은 발급 응답 1회).
- 브로커 토큰(OPENBAO_TOKEN)은 정책 `aegis-broker`: 역할로 토큰 만들기 + accessor 조회·갱신·회수만. 루트 토큰을 쓰지 않는다.
- Vault(BUSL)는 기본값에서 제외(MSG-027) — 같은 API 라 OPENBAO_ADDR 만 바꾸면 붙지만 지원 대상은 OpenBao(MPL-2.0).
- 운영형 클러스터(Epic 56): OPENBAO_ADDR 에 노드 주소 여러 개(쉼표) — 연결 실패·봉인(503)·리다이렉트(307)면 다음 노드로(대기 노드는 활성 노드로 전달).
  OPENBAO_CA_FILE·OPENBAO_CLIENT_CERT·OPENBAO_CLIENT_KEY 가 있으면 상호 TLS(파일이 바뀌면 다시 읽는다 — 인증서 회전).
  모든 노드가 미처리(선출 중)면 1초 쉬고 최대 3바퀴. 응답 시간 초과는 다시 보내지 않는다(이미 처리됐을 수 있는 발급의 중복 방지).
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request

from app.core.config import settings

ROLE = "aegis-lease"
HOLDER_POLICY = "aegis-lease-holder"
BROKER_POLICY = "aegis-broker"
_tls: dict = {"key": None, "ctx": None}
_node = {"i": 0}
ROUNDS = 3                                                              # 리더 선출(≈1 s) 동안 모든 노드가 307·503 일 수 있다


class BaoError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def enabled() -> bool:
    return settings.secrets_backend == "openbao"


def _token() -> str:
    t = settings.openbao_token
    if not t or t == "CHANGE_ME":
        raise BaoError(503, "OpenBao 브로커 토큰 미설정 (OPENBAO_TOKEN)")
    return t


def _addrs() -> list[str]:
    return [a.strip().rstrip("/") for a in settings.openbao_addr.split(",") if a.strip()]


def _ctx() -> ssl.SSLContext | None:
    files = [f for f in (settings.openbao_ca_file, settings.openbao_client_cert, settings.openbao_client_key) if f]
    if not files:
        return None
    key = tuple((f, os.path.getmtime(f)) for f in files if os.path.exists(f))
    if _tls["key"] != key:
        c = ssl.create_default_context(cafile=settings.openbao_ca_file or None)
        if settings.openbao_client_cert:
            c.load_cert_chain(settings.openbao_client_cert, settings.openbao_client_key or None)
        _tls.update(key=key, ctx=c)
    return _tls["ctx"]


def _call(method: str, path: str, body: dict | None = None, auth: bool = True) -> dict:
    headers = {"content-type": "application/json"} | ({"X-Vault-Token": _token()} if auth else {})
    data = json.dumps(body).encode() if body is not None else None
    addrs, last = _addrs(), None
    for k in range(len(addrs) * ROUNDS):
        if k and k % len(addrs) == 0:
            time.sleep(1.0)                                             # 한 바퀴 모두 미처리(선출 중) — 잠깐 쉬고 다시
        i = (_node["i"] + k) % len(addrs)
        req = urllib.request.Request(f"{addrs[i]}/v1/{path}", method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5, context=_ctx()) as r:
                raw = r.read()
                _node["i"] = i
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                errs = json.loads(e.read() or b"{}").get("errors") or []
            except ValueError:
                errs = []
            last = BaoError(e.code, "; ".join(errs) or f"HTTP {e.code}")
            if e.code not in (307, 503):                                # 봉인·활성 노드 없음(503)·선출 중 대기 노드 리다이렉트(307) = 처리 안 됨 → 다음 노드
                raise last from e
        except urllib.error.URLError as e:
            last = BaoError(503, f"OpenBao 연결 실패 — {e}")
            if not isinstance(e.reason, (ConnectionError, socket.gaierror, ssl.SSLError)):
                raise last from e                                       # 시간 초과 등 — 처리됐을 수 있어 다시 보내지 않는다
        except (TimeoutError, OSError) as e:
            raise BaoError(503, f"OpenBao 연결 실패 — {e}") from e
    raise last or BaoError(503, "OpenBao 주소 없음 (OPENBAO_ADDR)")


def create(ttl_sec: int, meta: dict) -> dict:
    """→ {token, accessor, ttl}. meta 값은 문자열만(OpenBao 제약)."""
    r = _call("POST", f"auth/token/create/{ROLE}", {
        "ttl": f"{ttl_sec}s", "renewable": True, "no_default_policy": True, "policies": [HOLDER_POLICY],
        "display_name": f"aegis-{meta.get('lease', '')}", "meta": {k: str(v) for k, v in meta.items()}})
    a = r["auth"]
    return {"token": a["client_token"], "accessor": a["accessor"], "ttl": int(a["lease_duration"])}


def lookup(accessor: str) -> dict | None:
    """→ 토큰 정보(ttl·expire_time·meta) 또는 None(회수·만료로 없음)."""
    try:
        return _call("POST", "auth/token/lookup-accessor", {"accessor": accessor})["data"]
    except BaoError as e:
        if e.status == 400:                                             # invalid accessor — 회수·만료로 없음
            return None
        raise


def renew(accessor: str, increment_sec: int) -> int:
    """→ 새 남은 수명(초). explicit_max_ttl 을 넘지 않는다(OpenBao 가 자른다)."""
    r = _call("POST", "auth/token/renew-accessor", {"accessor": accessor, "increment": f"{increment_sec}s"})
    return int(r["auth"]["lease_duration"])


def revoke(accessor: str) -> None:
    try:
        _call("POST", "auth/token/revoke-accessor", {"accessor": accessor})
    except BaoError as e:
        if e.status != 400:                                             # 이미 없음 = 회수된 것과 같다
            raise


def status() -> dict:
    """봉인·초기화 상태도 200 으로 받아 구분한다(운영형 재기동 뒤 '봉인됨' 을 '연결 불가' 와 다르게 보인다, Epic 46)."""
    try:
        h = _call("GET", "sys/health?sealedcode=200&uninitcode=200&standbyok=true", auth=False)
        return {"backend": "openbao", "addr": settings.openbao_addr, "sealed": h.get("sealed"), "initialized": h.get("initialized"),
                "version": h.get("version"), "ok": bool(h.get("initialized")) and not h.get("sealed"),
                "node": _addrs()[_node["i"] % len(_addrs())], "standby": bool(h.get("standby")), "tls": _ctx() is not None}
    except BaoError as e:
        return {"backend": "openbao", "addr": settings.openbao_addr, "ok": False, "error": e.msg}
