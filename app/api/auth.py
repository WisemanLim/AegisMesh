"""인증·사용자·테넌트 API (SCR-A06·B02·R01·R02, FR-P13·D5-01·02·03)."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import auth, fido, geo, ledger, mfa, models, sso, tenancy
from app.api.deps import Ctx, ctx, need, platform_scope, session
from app.core.config import settings

public = APIRouter(prefix="/v1/auth", tags=["auth"])
router = APIRouter(prefix="/v1", tags=["auth"], dependencies=[Depends(ctx)])


def _jkt(request: Request) -> str | None:
    """로그인·2단계·SSO 콜백 요청의 DPoP 증명 → 세션에 묶을 키 지문(없으면 바인딩 없음). 잘못된 증명은 400."""
    p, err = mfa.proof_key(request.headers.get("dpop"), request, None)
    if err:
        raise HTTPException(400, f"DPoP 증명 오류({err})")
    return p["jkt"] if p else None


def _err(exc: Exception):
    if isinstance(exc, (auth.AuthError, tenancy.TenantError, sso.SsoError)):
        raise HTTPException(exc.status, exc.msg) from exc
    raise exc


# ── 공개: 설정·부트스트랩·로그인 ─────────────────────────────────
@public.get("/config")
def config(s: Session = Depends(session)):
    """로그인 화면 구성 — 정적 비밀번호 외 SSO 슬롯, 첫 실행 여부."""
    c, on = sso.config(s), sso.enabled(s)
    return {"bootstrapRequired": auth.bootstrap_required(s), "local": True,
            "oidc": {"enabled": on, "issuer": c["issuer"], "clientId": c["clientId"], "mfaRequired": c["mfaRequired"]},
            "passwordLogin": "break_glass" if on else "all",
            "session": {"ttlHours": auth.SESSION_TTL.total_seconds() / 3600,
                        "idleMinutes": auth.SESSION_IDLE.total_seconds() / 60},
            "passwordMin": auth.MIN_PASSWORD, "lockAfter": auth.LOCK_AFTER,
            "mfa": {"webauthn": True, "totp": True, "rpId": settings.webauthn_rp_id}, "dpop": True}


class BootstrapIn(BaseModel):
    token: str = Field(min_length=8)
    username: str
    displayName: str = ""
    password: str
    tenantId: str = "default"
    tenantName: str = ""
    lang: str = Field("ko", pattern="^(ko|en)$")


@public.post("/bootstrap", status_code=201)
def bootstrap(body: BootstrapIn, request: Request, s: Session = Depends(session)):
    """첫 실행 ① (SCR-A06) — 1회용 토큰으로 비상(break-glass) 플랫폼 관리자 + 첫 테넌트. 토큰은 즉시 폐기."""
    s.info["tenant_scope"] = "*"                       # 첫 테넌트·정책 생성(시스템 작업)
    try:
        auth.use_bootstrap(s, body.token)
        if body.tenantId != "default" and s.get(models.Tenant, body.tenantId) is None:
            tenancy.create(s, body.tenantId, body.tenantName or body.tenantId, body.username, lang=body.lang)
        elif body.tenantName and (t := s.get(models.Tenant, body.tenantId)):
            t.name, t.lang = body.tenantName, body.lang
        u = auth.create_user(s, None, body.username, body.displayName, ["platform_admin"], None, body.password,
                             break_glass=True)
        row, token = auth.issue(s, u, "session", request.headers.get("user-agent", "")[:120])
        mfa.bind(row, request, _jkt(request), "none")
        ledger.append(s, "auth", u.id, {"event": "bootstrap_used", "user": u.username, "tenant": body.tenantId})
    except (auth.AuthError, tenancy.TenantError) as exc:
        s.rollback()
        _err(exc)
    s.commit()
    return {"token": token, "user": auth.out(u), "tenant": body.tenantId}


class LoginIn(BaseModel):
    username: str
    password: str
    reason: str = Field("", max_length=300)          # SSO 사용 중 비상 관리자 로그인 사유(필수)


@public.post("/login")
def login(body: LoginIn, request: Request, s: Session = Depends(session)):
    s.info["tenant_scope"] = "*"                       # 로그인 기록은 사용자 홈 체인(플랫폼·테넌트)에 남긴다
    glass = sso.enabled(s)
    if glass:                                          # FR-D5-01 — SSO 가 켜지면 정적 비밀번호는 봉인된 비상 관리자만
        if len(body.reason.strip()) < 4:
            raise HTTPException(400, "조직 SSO 사용 중 — 비밀번호 로그인은 비상 관리자만, 사유 필요 (FR-D5-01)")
        u = s.scalars(select(models.User).where(models.User.username == body.username.strip().lower())).first()
        if u is None or not u.break_glass:
            raise HTTPException(403, "조직 SSO 사용 중 — 비밀번호 로그인은 비상(break-glass) 관리자만 (FR-D5-01)")
    jkt = _jkt(request)
    try:
        u = auth.verify_login(s, body.username, body.password)
    except auth.AuthError as exc:
        _err(exc)
    if mfa.methods(s, u):                              # SCR-B02 ② — 2단계(패스키 우선·OTP 대체) 뒤에 세션
        opts = mfa.assertion_options(s, u, "login", jkt, {"reason": body.reason.strip()[:300], "glass": glass})
        s.commit()
        return {"mfa": opts}
    token, row = auth.start_session(s, u, request.headers.get("user-agent", "")[:120])
    mfa.bind(row, request, jkt, "none")
    enroll = mfa.required(s, u)                         # OQ3 — 특권 역할·테넌트 all 인데 수단이 없으면 등록 전용 세션
    if enroll:
        row.state, row.review_reason = "enroll", "2단계 등록 필요"
    if glass:
        ledger.append(s, "auth", u.id, {"event": "break_glass_login", "user": u.username, "session": row.id,
                                        "reason": body.reason.strip()}, auth.home_chain(u))
    s.commit()
    return {"token": token, "expiresAt": row.expires_at.isoformat(), "user": auth.out(u), "dpop": bool(jkt), "mfaEnrolled": False,
            "enrollRequired": enroll}


class MfaIn(BaseModel):
    ticket: str = Field(min_length=8, max_length=64)
    credential: dict | None = None                     # navigator.credentials.get() 결과(base64url)
    code: str | None = Field(None, max_length=8)       # 인증 앱 OTP


@public.post("/mfa:verify")
def mfa_verify(body: MfaIn, request: Request, s: Session = Depends(session)):
    """로그인 2단계 — 패스키 assertion 또는 OTP. 1단계에서 DPoP 키를 냈다면 같은 키의 증명이 있어야 한다."""
    s.info["tenant_scope"] = "*"
    try:
        ch = mfa.take(s, body.ticket, "login")
        u = s.get(models.User, ch.user_id)
        if u is None or not u.active:
            raise auth.AuthError(401, "비활성 계정")
        if u.locked_until and auth._utc(u.locked_until) > auth.utcnow():
            raise auth.AuthError(423, "로그인 실패 누적으로 잠김")
        if ch.jkt and _jkt(request) != ch.jkt:
            raise auth.AuthError(401, "DPoP 키가 1단계와 다르다")
        used = mfa.check(s, u, ch, body.credential, body.code)
        token, row = auth.start_session(s, u, request.headers.get("user-agent", "")[:120], used)
        mfa.bind(row, request, ch.jkt, used)
        if (ch.meta or {}).get("glass"):
            ledger.append(s, "auth", u.id, {"event": "break_glass_login", "user": u.username, "session": row.id,
                                            "reason": ch.meta.get("reason", "")}, auth.home_chain(u))
    except auth.AuthError as exc:
        s.commit()                                     # 대기표 소모·실패 기록은 남긴다
        _err(exc)
    s.commit()
    return {"token": token, "expiresAt": row.expires_at.isoformat(), "user": auth.out(u), "dpop": bool(ch.jkt), "mfa": used}


@public.get("/oidc/start")
def oidc_start(redirect: str, next: str = "/overview", s: Session = Depends(session)):
    """조직 SSO 로그인 시작 (SCR-B02 #1) — 인가 코드 + PKCE(S256). 콘솔이 브라우저를 돌려준 URL 로 보낸다."""
    try:
        url = sso.start(s, next, redirect)
    except sso.SsoError as exc:
        _err(exc)
    s.commit()
    return {"url": url}


class CallbackIn(BaseModel):
    code: str = Field(min_length=1, max_length=4096)
    state: str = Field(min_length=1, max_length=64)


@public.post("/oidc/callback")
def oidc_callback(body: CallbackIn, request: Request, s: Session = Depends(session)):
    """IdP 콜백 — code 교환(code_verifier) · ID 토큰 검증 · MFA · 그룹→역할 → 세션. 거부도 원장에 남긴다."""
    s.info["tenant_scope"] = "*"
    jkt = _jkt(request)
    try:
        u, token, row, next_ = sso.callback(s, body.code, body.state, request.headers.get("user-agent", "")[:120])
    except sso.SsoError as exc:
        s.commit()                                     # state 소모·거부 기록은 남긴다
        _err(exc)
    mfa.bind(row, request, jkt, "sso")                 # IdP 가 MFA 를 확인(amr) — 세션은 콘솔 키에 묶는다
    s.commit()
    return {"token": token, "expiresAt": row.expires_at.isoformat(), "user": auth.out(u), "next": next_}


@public.post("/oidc/backchannel-logout")
async def oidc_backchannel_logout(request: Request, s: Session = Depends(session)):
    """OIDC Back-Channel Logout — IdP 가 보낸 logout_token(서명 JWT)으로 그 사용자 세션 전부 폐기. 오류는 400(규격)."""
    s.info["tenant_scope"] = "*"
    form = await request.form()
    try:
        r = sso.backchannel_logout(s, str(form.get("logout_token") or ""))
    except sso.SsoError as exc:
        s.rollback()
        raise HTTPException(400, exc.msg) from exc
    s.commit()
    return r


# ── 로그인 주체 ───────────────────────────────────────────────
class LogoutIn(BaseModel):
    postLogoutRedirect: str | None = Field(None, max_length=300)


@router.post("/auth/logout")
def logout(body: LogoutIn | None = None, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    platform_scope(s, c)
    row = s.get(models.AuthSession, c.session_id)
    row.revoked_at = auth.utcnow()
    ledger.append(s, "auth", c.user.id, {"event": "logout", "user": c.name, "session": row.id}, auth.home_chain(c.user))
    s.commit()
    idp = sso.logout_url(s, body.postLogoutRedirect if body else None) if row.mfa == "sso" else None   # RP-Initiated Logout
    return {"ok": True, "idpLogout": idp}


@router.get("/auth/me")
def me(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    tenants = (list(s.scalars(select(models.Tenant).where(models.Tenant.active.is_(True)).order_by(models.Tenant.id)))
               if c.platform else [s.get(models.Tenant, c.user.tenant)])
    row = s.get(models.AuthSession, c.session_id) if c.session_id else None
    return auth.out(c.user) | {"scope": c.scope, "permissions": sorted(c.perms), "session": c.session_id,
                               "reauthRequired": bool(row and row.state == "review"), "reviewReason": row.review_reason if row else None,
                               "enrollRequired": bool(row and row.state == "enroll"),
                               "binding": {"dpop": bool(row.jkt), "mfa": row.mfa, "device": row.device, "location": row.location,
                                           "geo": row.geo} if row else None,
                               "roleNames": {r: auth.ROLES[r] for r in c.user.roles if r in auth.ROLES},
                               "tenants": [{"id": t.id, "name": t.name} for t in tenants if t]}


@router.get("/auth/sessions")
def my_sessions(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    rows = s.scalars(select(models.AuthSession).where(models.AuthSession.user_id == c.user.id)
                     .order_by(models.AuthSession.created_at.desc()).limit(50))
    return {"items": [auth.session_out(r, c.session_id) for r in rows]}


@router.post("/auth/sessions/{sid}:revoke")
def revoke_session(sid: str, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    platform_scope(s, c)
    row = s.get(models.AuthSession, sid)
    owner = s.get(models.User, row.user_id) if row and row.user_id else None
    if owner is None or (owner.id != c.user.id and ("user.admin" not in c.perms or not c.visible(owner.tenant or "*"))):
        raise HTTPException(404, f"session {sid} 없음")
    row.revoked_at = row.revoked_at or auth.utcnow()
    ledger.append(s, "auth", owner.id, {"event": "session_revoked", "session": sid, "kind": row.kind, "by": c.name},
                  auth.home_chain(owner))
    s.commit()
    return auth.session_out(row, c.session_id)


@router.post("/auth/sessions:revoke-others")
def revoke_others(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    """다른 세션 모두 종료 (SCR-B02 ③) — 현재 세션만 남긴다."""
    platform_scope(s, c)
    rows = list(s.scalars(select(models.AuthSession).where(models.AuthSession.user_id == c.user.id, models.AuthSession.kind == "session",
                                                           models.AuthSession.revoked_at.is_(None), models.AuthSession.id != c.session_id)))
    for r in rows:
        r.revoked_at = auth.utcnow()
    ledger.append(s, "auth", c.user.id, {"event": "sessions_revoked", "count": len(rows), "by": c.name}, auth.home_chain(c.user))
    s.commit()
    return {"revoked": len(rows)}


# ── 2단계 인증 수단·재인증 (SCR-B02 ②·⑤) ─────────────────────────
def _human(c: Ctx) -> None:
    if c.user.kind != "human" or not c.session_id:
        raise HTTPException(403, "로그인 세션(사람)만")


@router.get("/auth/mfa")
def my_mfa(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    return {"methods": mfa.methods(s, c.user), "totp": c.user.totp_enabled, "required": mfa.required(s, c.user),
            "policy": mfa.policy_of(s, c.user.tenant),
            "webauthn": [{"id": r.id, "name": r.name, "alg": r.alg, "transports": r.transports, "createdAt": r.created_at.isoformat(),
                          "lastUsedAt": r.last_used_at.isoformat() if r.last_used_at else None} for r in mfa.creds(s, c.user)]}


@router.post("/auth/webauthn/register:options")
def webauthn_options(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    platform_scope(s, c)
    r = mfa.registration_options(s, c.user)
    s.commit()
    return r


class RegisterIn(BaseModel):
    ticket: str = Field(min_length=8, max_length=64)
    credential: dict
    name: str = Field("passkey", max_length=120)


@router.post("/auth/webauthn/register", status_code=201)
def webauthn_register(body: RegisterIn, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    platform_scope(s, c)
    try:
        row = mfa.register(s, c.user, body.ticket, body.credential, body.name)
    except auth.AuthError as exc:
        s.commit()
        _err(exc)
    mfa.unlock_enrollment(s, s.get(models.AuthSession, c.session_id), c.user, "webauthn")
    s.commit()
    return {"id": row.id, "name": row.name, "alg": row.alg}


@router.delete("/auth/webauthn/{cid}", status_code=204)
def webauthn_delete(cid: str, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    platform_scope(s, c)
    row = s.get(models.WebAuthnCredential, cid)
    if row is None or row.user_id != c.user.id:
        raise HTTPException(404, "인증기 없음")
    s.delete(row)
    ledger.append(s, "auth", c.user.id, {"event": "mfa_removed", "method": "webauthn", "credential": cid[:16], "by": c.name}, auth.home_chain(c.user))
    s.commit()


@router.post("/auth/totp:setup")
def totp_setup(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    """인증 앱 등록 시작 — 비밀은 이 응답에서만 보인다(봉인 저장). 확인 코드가 맞아야 켜진다."""
    _human(c)
    platform_scope(s, c)
    r = mfa.totp_setup(s, c.user)
    s.commit()
    return r


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@router.post("/auth/totp:confirm")
def totp_confirm(body: CodeIn, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    platform_scope(s, c)
    try:
        mfa.totp_confirm(s, c.user, body.code)
    except auth.AuthError as exc:
        _err(exc)
    mfa.unlock_enrollment(s, s.get(models.AuthSession, c.session_id), c.user, "totp")
    s.commit()
    return {"totp": True}


@router.delete("/auth/totp", status_code=204)
def totp_delete(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    platform_scope(s, c)
    c.user.totp_secret, c.user.totp_enabled, c.user.totp_last_step = None, False, None
    ledger.append(s, "auth", c.user.id, {"event": "mfa_removed", "method": "totp", "by": c.name}, auth.home_chain(c.user))
    s.commit()


@router.post("/auth/reauth:options")
def reauth_options(s: Session = Depends(session), c: Ctx = Depends(ctx)):
    _human(c)
    platform_scope(s, c)
    if not mfa.methods(s, c.user):
        return {"methods": [], "password": True}
    r = mfa.assertion_options(s, c.user, "reauth")
    s.commit()
    return r


class ReauthIn(BaseModel):
    ticket: str | None = Field(None, max_length=64)
    credential: dict | None = None
    code: str | None = Field(None, max_length=8)
    password: str | None = Field(None, max_length=200)


@router.post("/auth/reauth")
def reauth(body: ReauthIn, request: Request, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    """재인증 (MSG-030) — 새 위치·기기 감지로 제한된 세션을 현재 기기·위치로 다시 묶는다."""
    _human(c)
    platform_scope(s, c)
    try:
        r = mfa.reauth(s, s.get(models.AuthSession, c.session_id), c.user, request, body.ticket, body.credential, body.code, body.password)
    except auth.AuthError as exc:
        s.commit()
        _err(exc)
    s.commit()
    return r


# ── 테넌트 로그인 정책 (OQ3) ─────────────────────────────────────
class AuthPolicyIn(BaseModel):
    mfa: str = Field("privileged", pattern="^(privileged|all)$")
    aaguids: list[str] = Field(default_factory=list, max_length=50)


@router.get("/tenants/{tid}/auth-policy")
def get_auth_policy(tid: str, s: Session = Depends(session), c: Ctx = Depends(ctx)):
    platform_scope(s, c)
    if not c.visible(tid) or s.get(models.Tenant, tid) is None:
        raise HTTPException(404, f"tenant {tid} 없음")
    return mfa.policy_of(s, tid) | {"privilegedRoles": sorted(mfa.PRIVILEGED)}


@router.put("/tenants/{tid}/auth-policy")
def put_auth_policy(tid: str, body: AuthPolicyIn, s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    """2단계 강제 범위(특권 역할 = 기본, all = 전원)·인증기 AAGUID 허용목록. 특권 역할 강제는 끌 수 없다."""
    platform_scope(s, c)
    t = s.get(models.Tenant, tid)
    if t is None or not c.visible(tid):
        raise HTTPException(404, f"tenant {tid} 없음")
    import re as _re
    ids = sorted({a.replace("-", "").lower() for a in body.aaguids})
    if any(not _re.fullmatch(r"[0-9a-f]{32}", a) for a in ids):
        raise HTTPException(422, "AAGUID = 16바이트 16진수(대시 허용)")
    t.auth_policy = {"mfa": body.mfa, "aaguids": ids}
    ledger.append(s, "auth", tid, {"event": "auth_policy_set", "policy": t.auth_policy, "by": c.name}, tid)
    s.commit()
    return mfa.policy_of(s, tid) | {"privilegedRoles": sorted(mfa.PRIVILEGED)}


@router.get("/auth/mds")
def mds_status(c: Ctx = Depends(need("read"))):
    """FIDO MDS3 스냅숏 상태(Epic 54) — 번호·다음 갱신·낡음·기종 수·서명자·고정 루트·유출/우회 보고 기종 수."""
    return fido.status()


@router.get("/auth/geoip")
def geoip_status(ip: str | None = None, c: Ctx = Depends(need("read"))):
    """지오 IP DB 상태(Epic 55) — 출처·빌드 날짜·sha256·불가능한 이동 임계. ip 를 주면 그 IP 의 분류·위치(운영 확인용)."""
    return geo.status() | ({"lookup": geo.lookup(ip) | {"label": geo.label(geo.lookup(ip))} if geo.lookup(ip) else None} if ip else {})


# ── 사용자·역할 (SCR-R02) ──────────────────────────────────────
def _scoped_user(s: Session, c: Ctx, uid: str) -> models.User:
    u = s.get(models.User, uid)
    if u is None or (not c.platform and u.tenant != c.user.tenant):
        raise HTTPException(404, f"user {uid} 없음")
    return u


@router.get("/roles")
def roles(c: Ctx = Depends(need("read"))):
    return {"roles": [{"id": k, "name": v, "permissions": sorted(p for p, rs in auth.PERMS.items() if k in rs)}
                      for k, v in auth.ROLES.items()],
            "platformOnly": sorted(auth.PLATFORM_ONLY)}


@router.get("/users")
def list_users(s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    q = select(models.User).order_by(models.User.tenant, models.User.username)
    if not c.platform:
        q = q.where(models.User.tenant == c.user.tenant)
    elif c.scope != "*":
        q = q.where(models.User.tenant == c.scope)
    return {"items": [auth.out(u) for u in s.scalars(q)]}


class UserIn(BaseModel):
    username: str
    displayName: str = ""
    roles: list[str] = []
    tenant: str | None = None
    password: str | None = None
    kind: str = Field("human", pattern="^(human|service)$")


@router.post("/users", status_code=201)
def add_user(body: UserIn, s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    try:
        u = auth.create_user(s, c, body.username, body.displayName, body.roles, body.tenant, body.password, body.kind)
    except (auth.AuthError, tenancy.TenantError) as exc:
        _err(exc)
    s.commit()
    return auth.out(u)


class UserPatch(BaseModel):
    roles: list[str] | None = None
    active: bool | None = None
    displayName: str | None = None
    password: str | None = None


@router.patch("/users/{uid}")
def patch_user(uid: str, body: UserPatch, s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    u = _scoped_user(s, c, uid)
    try:
        auth.update_user(s, c, u, body.roles, body.active, body.displayName, body.password)
    except auth.AuthError as exc:
        _err(exc)
    s.commit()
    return auth.out(u)


@router.get("/users/{uid}/tokens")
def user_tokens(uid: str, s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    u = _scoped_user(s, c, uid)
    rows = s.scalars(select(models.AuthSession).where(models.AuthSession.user_id == u.id)
                     .order_by(models.AuthSession.created_at.desc()).limit(50))
    return {"items": [auth.session_out(r) for r in rows]}


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    ttlDays: int | None = Field(None, ge=1, le=3650)


@router.post("/users/{uid}/tokens", status_code=201)
def add_token(uid: str, body: TokenIn, s: Session = Depends(session), c: Ctx = Depends(need("user.admin"))):
    """API 토큰(서비스 계정 판정 호출용). 원문은 이 응답 1회만 — 서버에는 id 만 남는다."""
    u = _scoped_user(s, c, uid)
    if not u.active:
        raise HTTPException(409, "비활성 계정")
    row, token = auth.issue(s, u, "api_token", body.name, timedelta(days=body.ttlDays) if body.ttlDays else None)
    ledger.append(s, "auth", u.id, {"event": "token_issued", "token": row.id, "name": body.name, "by": c.name},
                  auth.home_chain(u))
    s.commit()
    return auth.session_out(row) | {"token": token}


@router.get("/authz:check")
def authz_check(user: str, perm: str, tenant: str | None = None, s: Session = Depends(session),
                c: Ctx = Depends(need("user.admin"))):
    u = s.scalars(select(models.User).where(models.User.username == user.lower())).first()
    if u is None or (not c.platform and u.tenant != c.user.tenant):
        raise HTTPException(404, f"user {user} 없음")
    return {"user": u.username, "perm": perm, "tenant": tenant} | auth.check(u, perm, tenant)


# ── 테넌트 (SCR-R01) ──────────────────────────────────────────
@router.get("/tenants")
def list_tenants(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    q = select(models.Tenant).order_by(models.Tenant.id)
    if not c.platform:
        q = q.where(models.Tenant.id == c.user.tenant)
    return {"items": [tenancy.out(t, s) for t in s.scalars(q)]}


class TenantIn(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=120)
    isolation: str = "logical"
    retentionDays: int = Field(90, ge=1, le=3650)
    region: str = "kr"
    lang: str = Field("ko", pattern="^(ko|en)$")


@router.post("/tenants", status_code=201)
def add_tenant(body: TenantIn, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    try:
        t = tenancy.create(s, body.id, body.name, c.name, body.isolation, body.retentionDays, body.region, body.lang)
    except tenancy.TenantError as exc:
        _err(exc)
    s.commit()
    return tenancy.out(t, s)


class TenantPatch(BaseModel):
    name: str | None = None
    retentionDays: int | None = Field(None, ge=1, le=3650)
    active: bool | None = None


@router.patch("/tenants/{tid}")
def patch_tenant(tid: str, body: TenantPatch, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    t = s.get(models.Tenant, tid)
    if t is None:
        raise HTTPException(404, f"tenant {tid} 없음")
    try:
        tenancy.update(s, t, c.name, body.name, body.retentionDays, body.active)
    except tenancy.TenantError as exc:
        _err(exc)
    s.commit()
    return tenancy.out(t, s)


@router.post("/tenants:isolation-test")
def isolation_test(s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    r = tenancy.isolation_test(s, c.name)
    s.commit()
    return r


@router.get("/tenants/isolation-test")
def last_isolation_test(s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    return tenancy.last_test(s) or {}


# ── 조직 SSO 설정 (SCR-A06 ②, 플랫폼 관리자) ─────────────────────
class SsoIn(BaseModel):
    issuer: str = Field(min_length=8, max_length=255)
    clientId: str = Field(min_length=1, max_length=120)
    groupsClaim: str = Field("groups", max_length=64)
    mfaRequired: bool = True
    acrValues: list[str] = ["mfa"]
    enabled: bool = False


class MapIn(BaseModel):
    group: str = Field(min_length=1, max_length=120)
    role: str
    tenant: str | None = None


class MapsIn(BaseModel):
    items: list[MapIn]


def _sso_view(s: Session) -> dict:
    return sso.config(s) | {"mappings": sso.mappings(s), "recent": sso.recent(s),
                            "roles": {k: v for k, v in auth.ROLES.items() if k != "service"},
                            "clientSecret": bool(settings.oidc_client_secret), "backchannel": bool(settings.oidc_backchannel_map)}


@router.get("/auth/sso")
def sso_get(s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    platform_scope(s, c)
    return _sso_view(s)


@router.put("/auth/sso")
def sso_put(body: SsoIn, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    platform_scope(s, c)
    try:
        sso.save_config(s, c.name, body.issuer, body.clientId, body.groupsClaim, body.mfaRequired, body.acrValues, body.enabled)
    except sso.SsoError as exc:
        s.rollback()
        _err(exc)
    s.commit()
    return _sso_view(s)


@router.put("/auth/sso/mappings")
def sso_mappings(body: MapsIn, s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    platform_scope(s, c)
    if not body.items and sso.enabled(s):
        raise HTTPException(422, "SSO 사용 중에는 매핑을 모두 지울 수 없다 — 먼저 SSO 끄기")
    try:
        sso.save_mappings(s, c.name, [m.model_dump() for m in body.items])
    except sso.SsoError as exc:
        s.rollback()
        _err(exc)
    s.commit()
    return _sso_view(s)


@router.post("/auth/sso:test")
def sso_test(s: Session = Depends(session), c: Ctx = Depends(need("tenant.admin"))):
    platform_scope(s, c)
    r = sso.test(s, c.name)
    s.commit()
    return r
