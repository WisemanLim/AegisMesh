"""조직 SSO — OIDC 인가 코드 + PKCE (FR-D5-01·03, SCR-A06·B02).

start(next) → IdP 인가 URL(state·nonce·S256 code_challenge·acr_values) → 콜백 code → 토큰 교환(code_verifier)
→ ID 토큰 검증(RS256·JWKS·iss·aud·azp·exp·nonce) → MFA(acr/amr) → IdP 그룹 → 역할 매핑(미매핑 거부) → 세션.
SSO 가 켜지면 비밀번호 로그인은 비상(break-glass) 관리자만 — 사유 필수, 원장 기록·알림(API 계층).
code_verifier·nonce 는 서버(oidc_requests)에만 두고 state 는 1회용이다.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import auth, ledger, models, tenancy
from app.core.config import settings

REQUEST_TTL = timedelta(minutes=10)
CACHE_SEC = 300
SKEW_SEC = 60
MFA_AMR = {"mfa", "otp", "hwk", "swk", "sc", "fpt", "pop"}       # RFC 8176 — 소지·생체 요소
EVENTS = ("sso_login", "sso_denied", "break_glass_login", "sso_config", "sso_mappings", "sso_test")
_cache: dict[str, tuple[float, dict]] = {}


class SsoError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


# ── 설정 ────────────────────────────────────────────────────
def config(s: Session) -> dict:
    row = s.get(models.SsoConfig, "default")
    if row is None:                                   # 콘솔에서 저장 전에는 env 초기값
        return {"issuer": settings.oidc_issuer or "", "clientId": settings.oidc_client_id or "", "groupsClaim": "groups",
                "mfaRequired": True, "acrValues": ["mfa"], "enabled": bool(settings.oidc_issuer and settings.oidc_client_id),
                "source": "env", "updatedBy": None, "updatedAt": None}
    return {"issuer": row.issuer, "clientId": row.client_id, "groupsClaim": row.groups_claim, "mfaRequired": row.mfa_required,
            "acrValues": row.acr_values, "enabled": row.enabled, "source": "console", "updatedBy": row.updated_by,
            "updatedAt": row.updated_at.isoformat()}


def enabled(s: Session) -> bool:
    c = config(s)
    return bool(c["enabled"] and c["issuer"] and c["clientId"])


def save_config(s: Session, by: str, issuer: str, client_id: str, groups_claim: str, mfa_required: bool,
                acr_values: list[str], enable: bool) -> dict:
    issuer = issuer.strip().rstrip("/")
    if urllib.parse.urlparse(issuer).scheme not in ("http", "https"):
        raise SsoError(422, "Issuer 는 http(s) URL")
    if enable:
        discover(issuer, refresh=True)                # 켜기 전에 discovery·issuer 일치 확인
        if not mappings(s):
            raise SsoError(422, "그룹→역할 매핑이 없으면 아무도 로그인할 수 없다 — 매핑 먼저")
        if mfa_required and not acr_values:
            raise SsoError(422, "MFA 필수면 인정할 acr 값이 필요")
    row = s.get(models.SsoConfig, "default") or models.SsoConfig(id="default")
    row.issuer, row.client_id, row.groups_claim = issuer, client_id.strip(), groups_claim.strip() or "groups"
    row.mfa_required, row.acr_values, row.enabled = mfa_required, [a.strip() for a in acr_values if a.strip()], enable
    row.updated_by, row.updated_at = by, auth.utcnow()
    s.merge(row)
    s.flush()
    ledger.append(s, "auth", "sso", {"event": "sso_config", "by": by, "issuer": issuer, "clientId": row.client_id,
                                     "mfaRequired": mfa_required, "acrValues": row.acr_values, "enabled": enable})
    return config(s)


def mappings(s: Session) -> list[dict]:
    rows = s.scalars(select(models.SsoGroupMap).order_by(models.SsoGroupMap.group, models.SsoGroupMap.role))
    return [{"group": m.group, "role": m.role, "tenant": m.tenant} for m in rows]


def save_mappings(s: Session, by: str, items: list[dict]) -> list[dict]:
    seen = set()
    for m in items:
        if m["role"] not in auth.ROLES or m["role"] == "service":
            raise SsoError(422, f"알 수 없는 역할 {m['role']}")
        if m.get("tenant"):
            if m["role"] == "platform_admin":
                raise SsoError(422, "플랫폼 관리자는 테넌트에 매핑할 수 없다")
            if s.get(models.Tenant, m["tenant"]) is None:
                raise SsoError(404, f"tenant {m['tenant']} 없음")
        seen.add((m["group"].strip().lstrip("/"), m["role"], m.get("tenant") or None))
    s.execute(delete(models.SsoGroupMap))
    now = auth.utcnow()
    for g, r, t in sorted(seen, key=lambda x: (x[0], x[1], x[2] or "")):
        s.add(models.SsoGroupMap(group=g, role=r, tenant=t, created_by=by, created_at=now))
    s.flush()
    out = mappings(s)
    ledger.append(s, "auth", "sso", {"event": "sso_mappings", "by": by, "mappings": out})
    return out


# ── IdP 통신 (서버 간, 백채널 주소 치환) ─────────────────────────
def _backchannel(url: str) -> str:
    for pair in (settings.oidc_backchannel_map or "").split(","):
        src, _, dst = pair.partition("=")
        if src and dst and url.startswith(src.strip()):
            return dst.strip() + url[len(src.strip()):]
    return url


def _get_json(url: str) -> dict:
    req = urllib.request.Request(_backchannel(url), headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, ValueError) as exc:
        raise SsoError(502, f"IdP 호출 실패 {url}: {exc}") from exc


def _post_form(url: str, data: dict) -> dict:
    req = urllib.request.Request(_backchannel(url), data=urllib.parse.urlencode(data).encode(),
                                 headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except ValueError:
            body = {}
        raise SsoError(401, f"토큰 교환 실패: {body.get('error', exc.code)} {body.get('error_description', '')}".strip()) from exc
    except (urllib.error.URLError, ValueError) as exc:
        raise SsoError(502, f"IdP 토큰 엔드포인트 호출 실패: {exc}") from exc


def _cached(url: str, refresh: bool) -> dict:
    hit = _cache.get(url)
    if hit and not refresh and time.time() - hit[0] < CACHE_SEC:
        return hit[1]
    doc = _get_json(url)
    _cache[url] = (time.time(), doc)
    return doc


def discover(issuer: str, refresh: bool = False) -> dict:
    doc = _cached(f"{issuer}/.well-known/openid-configuration", refresh)
    if doc.get("issuer") != issuer:
        raise SsoError(502, f"discovery issuer 불일치 {doc.get('issuer')} ≠ {issuer}")
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(k):
            raise SsoError(502, f"discovery 에 {k} 없음")
    return doc


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s_: str) -> bytes:
    return base64.urlsafe_b64decode(s_ + "=" * (-len(s_) % 4))


def _rsa_key(doc: dict, kid: str | None) -> rsa.RSAPublicKey:
    for refresh in (False, True):                     # 모르는 kid 면 1회 재조회(IdP 키 회전)
        for k in _cached(doc["jwks_uri"], refresh).get("keys", []):
            if k.get("kty") == "RSA" and k.get("use", "sig") == "sig" and (kid is None or k.get("kid") == kid):
                n, e = (int.from_bytes(_unb64(k[x]), "big") for x in ("n", "e"))
                return rsa.RSAPublicNumbers(e, n).public_key()
    raise SsoError(401, f"서명 키 {kid} 를 JWKS 에서 찾을 수 없음")


def verify_id_token(token: str, doc: dict, client_id: str, nonce: str) -> dict:
    try:
        head_b, body_b, sig_b = token.split(".")
        head, claims = json.loads(_unb64(head_b)), json.loads(_unb64(body_b))
    except ValueError as exc:
        raise SsoError(401, "ID 토큰 형식 오류") from exc
    if head.get("alg") != "RS256":
        raise SsoError(401, f"지원하지 않는 서명 알고리즘 {head.get('alg')} (RS256 만)")
    try:
        _rsa_key(doc, head.get("kid")).verify(_unb64(sig_b), f"{head_b}.{body_b}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise SsoError(401, "ID 토큰 서명 불일치") from exc
    now = time.time()
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if claims.get("iss") != doc["issuer"]:
        raise SsoError(401, "ID 토큰 iss 불일치")
    if client_id not in auds or (len(auds) > 1 and claims.get("azp") != client_id):
        raise SsoError(401, "ID 토큰 aud·azp 불일치")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - SKEW_SEC:
        raise SsoError(401, "ID 토큰 만료")
    if claims.get("iat", now) > now + SKEW_SEC:
        raise SsoError(401, "ID 토큰 iat 가 미래")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise SsoError(401, "nonce 불일치 — 재전송 의심")
    if not claims.get("sub"):
        raise SsoError(401, "ID 토큰 sub 없음")
    return claims


def mfa_ok(claims: dict, c: dict) -> bool:
    if not c["mfaRequired"]:
        return True
    return claims.get("acr") in c["acrValues"] or bool(set(claims.get("amr") or []) & MFA_AMR)


def map_roles(s: Session, groups: list[str]) -> tuple[list[str], str | None]:
    rows = list(s.scalars(select(models.SsoGroupMap).where(models.SsoGroupMap.group.in_(groups or [""]))))
    if not rows:
        raise SsoError(403, (f"IdP 그룹 {groups} 이 역할에 매핑되지 않음" if groups else "IdP 그룹 없음 — 역할을 정할 수 없음")
                       + " — 로그인 거부 (SCR-A06)")
    tenants = {m.tenant for m in rows}
    if len(tenants) > 1:
        raise SsoError(403, f"그룹 매핑 테넌트 충돌 {sorted(t or '플랫폼' for t in tenants)} — 관리자 확인")
    return sorted({m.role for m in rows}), tenants.pop()


# ── 로그인 흐름 ──────────────────────────────────────────────
def start(s: Session, next_: str, redirect_uri: str) -> str:
    c = config(s)
    if not enabled(s):
        raise SsoError(409, "조직 SSO 미설정 — /admin/sso 에서 연결")
    u = urllib.parse.urlparse(redirect_uri)
    if u.scheme not in ("http", "https") or not u.netloc or u.path != "/auth/callback" or u.query:
        raise SsoError(422, "redirect_uri 는 <콘솔>/auth/callback")
    doc = discover(c["issuer"])
    now = auth.utcnow()
    s.execute(delete(models.OidcRequest).where(models.OidcRequest.created_at < now - REQUEST_TTL))
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    s.add(models.OidcRequest(state=state, nonce=nonce, verifier=verifier, redirect_uri=redirect_uri,
                             next=next_[:255] or "/overview", created_at=now))
    params = {"response_type": "code", "client_id": c["clientId"], "redirect_uri": redirect_uri,
              "scope": "openid profile email", "state": state, "nonce": nonce,
              "code_challenge": _b64u(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
    if c["mfaRequired"] and c["acrValues"]:
        params["acr_values"] = " ".join(c["acrValues"])
    ep = doc["authorization_endpoint"]
    return f"{ep}{'&' if '?' in ep else '?'}{urllib.parse.urlencode(params)}"


def _upsert(s: Session, claims: dict, roles: list[str], tenant: str | None) -> models.User:
    ext = f"{claims['iss']}#{claims['sub']}"
    name = claims.get("name") or claims.get("preferred_username") or ""
    u = s.scalars(select(models.User).where(models.User.external_id == ext)).first()
    if u is None:
        username = str(claims.get("preferred_username") or claims.get("email") or "").strip().lower()
        if not auth.USERNAME.match(username):
            raise SsoError(403, f"preferred_username '{username}' 형식 불가 (소문자·숫자·._@- 3~64자)")
        if s.scalars(select(models.User).where(models.User.username == username)).first():
            raise SsoError(409, f"로컬 계정 {username} 과 이름 충돌 — 관리자 확인 (계정 탈취 방지)")
        if tenant:
            try:
                tenancy.require(s, tenant)
            except tenancy.TenantError as exc:
                raise SsoError(exc.status, exc.msg) from exc
        u = models.User(id=f"usr_{secrets.token_hex(6)}", username=username, display_name=name or username, password_hash=None,
                        roles=roles, tenant=tenant, kind="human", active=True, break_glass=False, failed_logins=0,
                        created_by="sso", created_at=auth.utcnow(), external_id=ext)
        s.add(u)
        s.flush()
        ledger.append(s, "auth", u.id, {"event": "user_created", "user": username, "roles": roles, "kind": "human",
                                        "tenant": tenant, "breakGlass": False, "by": "sso"}, auth.home_chain(u))
        return u
    if not u.active:
        raise SsoError(403, "비활성 계정")
    if u.roles != roles or u.tenant != tenant:        # IdP 그룹이 기준 — 로그인마다 동기화
        ledger.append(s, "auth", u.id, {"event": "sso_roles_synced", "user": u.username, "before": {"roles": u.roles, "tenant": u.tenant},
                                        "after": {"roles": roles, "tenant": tenant}}, auth.home_chain(u))
        if u.tenant != tenant:
            auth.revoke_all(s, u)
        u.roles, u.tenant = roles, tenant
    u.display_name = name or u.display_name
    return u


def callback(s: Session, code: str, state: str, agent: str = "") -> tuple[models.User, str, models.AuthSession, str]:
    req = s.get(models.OidcRequest, state)
    if req is None or auth._utc(req.created_at) < auth.utcnow() - REQUEST_TTL:
        raise SsoError(400, "알 수 없거나 만료된 state — 다시 로그인")
    s.delete(req)                                     # 1회용
    s.flush()
    c = config(s)
    if not enabled(s):
        raise SsoError(409, "조직 SSO 미설정")
    doc = discover(c["issuer"])
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": req.redirect_uri,
            "client_id": c["clientId"], "code_verifier": req.verifier}
    if settings.oidc_client_secret:
        data["client_secret"] = settings.oidc_client_secret
    tok = _post_form(doc["token_endpoint"], data)
    if not tok.get("id_token"):
        raise SsoError(401, "토큰 응답에 id_token 없음")
    claims = verify_id_token(tok["id_token"], doc, c["clientId"], req.nonce)
    raw = claims.get(c["groupsClaim"]) or []
    groups = sorted({str(g).strip().lstrip("/") for g in (raw if isinstance(raw, list) else [raw])})
    who = claims.get("preferred_username") or claims["sub"]
    try:
        if not mfa_ok(claims, c):
            raise SsoError(403, f"MFA 필요 — acr {claims.get('acr')} · amr {claims.get('amr') or []} (FR-D5-01)")
        roles, tenant = map_roles(s, groups)
        user = _upsert(s, claims, roles, tenant)
    except SsoError as exc:
        known = s.scalars(select(models.User).where(models.User.external_id == f"{claims['iss']}#{claims['sub']}")).first()
        revoked = auth.revoke_all(s, known) if known is not None else 0     # 매핑 해제·MFA 미충족 → 기존 세션도 회수
        ledger.append(s, "auth", "sso", {"event": "sso_denied", "user": who, "groups": groups, "acr": claims.get("acr"),
                                         "reason": exc.msg, "revokedSessions": revoked})
        raise
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, auth.utcnow()
    row, token = auth.issue(s, user, "session", agent)
    ledger.append(s, "auth", user.id, {"event": "sso_login", "user": user.username, "session": row.id, "groups": groups,
                                       "roles": user.roles, "tenant": user.tenant, "acr": claims.get("acr"),
                                       "amr": claims.get("amr") or []}, auth.home_chain(user))
    return user, token, row, req.next


# ── 점검·이력 ────────────────────────────────────────────────
def recent(s: Session, limit: int = 10) -> list[dict]:
    rows = s.scalars(select(models.Evidence).where(models.Evidence.kind == "auth").order_by(models.Evidence.seq.desc()).limit(500))
    return [{"at": r.created_at, "seq": r.seq} | r.body for r in rows if r.body.get("event") in EVENTS][:limit]


def test(s: Session, by: str) -> dict:
    """연결 시험 (SCR-A06 #8) — discovery·서명 키·PKCE·매핑·비밀번호 로그인 비활성·최근 SSO 로그인 역할."""
    c = config(s)
    checks = []

    def add(id_, title, ok, detail):
        checks.append({"id": id_, "title": title, "ok": bool(ok), "detail": detail})

    doc = None
    try:
        doc = discover(c["issuer"], refresh=True) if c["issuer"] else None
        add("discovery", "OIDC discovery", doc, f"{c['issuer']} · 인가 {doc['authorization_endpoint']}" if doc else "Issuer 미설정")
    except SsoError as exc:
        add("discovery", "OIDC discovery", False, exc.msg)
    if doc:
        keys = _cached(doc["jwks_uri"], True).get("keys", [])
        rs = [k.get("kid") for k in keys if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"]
        add("keys", "서명 키 RS256", rs, f"RSA 서명 키 {len(rs)}개 {rs[:2]}")
        add("pkce", "PKCE S256", "S256" in doc.get("code_challenge_methods_supported", ["S256"]),
            f"지원 {doc.get('code_challenge_methods_supported', '미표시')}")
    maps = mappings(s)
    add("mappings", "그룹→역할 매핑", maps, f"{len(maps)}건 — 미매핑 사용자는 로그인 거부")
    add("mfa", "MFA 필수", c["mfaRequired"], f"인정 acr {c['acrValues']} 또는 amr {sorted(MFA_AMR)}")
    users = list(s.scalars(select(models.User).where(models.User.kind == "human", models.User.active.is_(True),
                                                      models.User.password_hash.is_not(None))))
    bg = [u.username for u in users if u.break_glass]
    add("password", "정적 비밀번호 로그인 비활성", bg and c["enabled"],
        f"{'켜짐 — ' if c['enabled'] else '꺼짐(SSO 미활성) — '}비상 관리자 {len(bg)} 만 허용 · 차단 대상 로컬 계정 {len(users) - len(bg)}")
    last = next((r for r in recent(s, 50) if r["event"] == "sso_login"), None)
    add("login", "시험 로그인 역할 확인", last, f"{last['user']} → {', '.join(auth.ROLES.get(r, r) for r in last['roles'])}"
        f"{' @' + last['tenant'] if last.get('tenant') else ''} (acr {last.get('acr')})" if last else "아직 SSO 로그인 없음")
    ok = all(x["ok"] for x in checks)
    ledger.append(s, "auth", "sso", {"event": "sso_test", "by": by, "ok": ok, "failed": [x["id"] for x in checks if not x["ok"]]})
    return {"ok": ok, "checks": checks, "at": auth.utcnow().isoformat(timespec="seconds")}


# ── IdP 로그아웃 연동 (OIDC Back-Channel Logout 1.0 · RP-Initiated Logout 1.0) ────────────
BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def backchannel_logout(s: Session, logout_token: str) -> dict:
    """IdP 가 보내는 logout_token(JWT) 검증 → 그 사용자의 세션 전부 폐기. 재전송(jti)은 거부."""
    c = config(s)
    if not enabled(s):
        raise SsoError(400, "조직 SSO 꺼짐")
    doc = discover(c["issuer"])
    try:
        head_b, body_b, sig_b = logout_token.split(".")
        head, claims = json.loads(_unb64(head_b)), json.loads(_unb64(body_b))
    except ValueError as exc:
        raise SsoError(400, "logout_token 형식 오류") from exc
    if head.get("alg") != "RS256":
        raise SsoError(400, "logout_token alg 는 RS256 만")
    try:
        _rsa_key(doc, head.get("kid")).verify(_unb64(sig_b), f"{head_b}.{body_b}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise SsoError(400, "logout_token 서명 불일치") from exc
    aud = claims.get("aud")
    now = time.time()
    if claims.get("iss") != doc["issuer"] or c["clientId"] not in (aud if isinstance(aud, list) else [aud]):
        raise SsoError(400, "logout_token iss·aud 불일치")
    if not isinstance(claims.get("iat"), (int, float)) or abs(now - claims["iat"]) > 300:
        raise SsoError(400, "logout_token iat 범위 밖")
    if BCL_EVENT not in (claims.get("events") or {}) or "nonce" in claims:
        raise SsoError(400, "logout_token events 누락 또는 nonce 포함")
    if not claims.get("sub") and not claims.get("sid"):
        raise SsoError(400, "logout_token sub·sid 없음")
    jti = str(claims.get("jti") or "")
    if not jti:
        raise SsoError(400, "logout_token jti 없음")
    jid = f"bcl:{hashlib.sha256(jti.encode()).hexdigest()[:40]}"
    if s.get(models.DpopJti, jid) is not None:
        raise SsoError(400, "logout_token 재전송")
    s.add(models.DpopJti(id=jid, seen_at=auth.utcnow()))
    u = s.scalars(select(models.User).where(models.User.external_id == f"{claims['iss']}#{claims.get('sub')}")).first() if claims.get("sub") else None
    n = auth.revoke_all(s, u) if u is not None else 0
    ledger.append(s, "auth", u.id if u else "unknown", {"event": "idp_backchannel_logout", "user": u.username if u else None,
                                                        "sid": claims.get("sid"), "revoked": n}, auth.home_chain(u) if u else ledger.PLATFORM)
    return {"user": u.username if u else None, "revoked": n}


def logout_url(s: Session, post_logout_redirect: str | None) -> str | None:
    """RP-Initiated Logout — 콘솔 로그아웃 뒤 IdP 세션도 끝내도록 end_session_endpoint 로 보낸다(없으면 None)."""
    if not enabled(s):
        return None
    c = config(s)
    try:
        end = discover(c["issuer"]).get("end_session_endpoint")
    except SsoError:
        return None
    if not end:
        return None
    q = {"client_id": c["clientId"]} | ({"post_logout_redirect_uri": post_logout_redirect} if post_logout_redirect else {})
    return f"{end}?{urllib.parse.urlencode(q)}"
