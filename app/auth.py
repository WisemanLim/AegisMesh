"""인증·인가 (SCR-B02·R02, FR-D5-01·02·03) — 로컬 계정 + 서명 세션·API 토큰 + 역할.

- 비밀번호: scrypt(N=2^14, r=8, p=1) + 16바이트 솔트. 5회 실패 → 15분 잠금.
- 토큰: am1.<세션 id>.<HMAC-SHA256(서버 비밀, id)> — DB 에는 id 만 둔다(DB 가 새도 토큰을 위조할 수 없다).
  세션 수명 8시간·유휴 30분, API 토큰은 회수 전까지(만료 선택). 회수·만료는 즉시 반영.
- 부트스트랩: 사용자가 없을 때 1회용 토큰(24시간)으로 첫 플랫폼 관리자(break-glass)·첫 테넌트를 만든다(SCR-A06).
- OIDC 는 설정 슬롯만(OIDC_ISSUER·OIDC_CLIENT_ID) — IdP 연동은 후속.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import kms, ledger, models
from app.core.config import settings

SESSION_TTL = timedelta(hours=8)
SESSION_IDLE = timedelta(minutes=30)
BOOTSTRAP_TTL = timedelta(hours=24)
LOCK_AFTER, LOCK_FOR = 5, timedelta(minutes=15)
MIN_PASSWORD = 12
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,63}$")

# 역할 8 유형(SCR-R02) + 서비스 계정. 인가 판단은 이 표 한 곳에서만(정책 결정점).
ROLES = {
    "platform_admin": "플랫폼 관리자", "security_engineer": "보안 엔지니어", "approver": "승인자",
    "compliance": "규제 대응", "developer": "에이전트 앱 개발자", "redteam": "레드팀",
    "auditor": "감사자(읽기 전용)", "tenant_admin": "테넌트 관리자", "service": "서비스 계정(판정 호출)",
}
PERMS: dict[str, frozenset[str]] = {k: frozenset(v) for k, v in {
    "read": set(ROLES) - {"service"},
    "judge": {"platform_admin", "security_engineer", "developer", "tenant_admin", "service"},
    "policy.write": {"platform_admin", "security_engineer", "tenant_admin"},
    "approve": {"approver"},
    "scan": {"platform_admin", "security_engineer", "tenant_admin"},
    "incident": {"platform_admin", "security_engineer"},
    "evidence.export": {"platform_admin", "security_engineer", "compliance", "auditor"},
    "report": {"platform_admin", "compliance", "auditor"},
    "agent.register": {"platform_admin", "developer"},
    "publisher": {"platform_admin"},
    "governance": {"platform_admin", "compliance"},
    "redteam": {"platform_admin", "redteam"},
    "tenant.admin": {"platform_admin"},
    "user.admin": {"platform_admin", "tenant_admin"},
    "identity": {"platform_admin", "security_engineer"},
    "sandbox": {"platform_admin", "security_engineer"},
    "secrets.lease": {"platform_admin", "security_engineer", "tenant_admin", "service"},
    "quality": {"platform_admin", "security_engineer", "tenant_admin"},          # 판정 이의·라벨 (SCR-O02)
    "quality.run": {"platform_admin", "security_engineer"},                     # 골든셋 재생 (플랫폼 범위)
    "privacy": {"platform_admin", "security_engineer", "compliance", "tenant_admin"},
    "compliance.write": {"platform_admin", "compliance"},                       # 공정성 측정·영향 평가·카드 생성·공개 요청 (SCR-N06·N07)   # 삭제 전파·학습 데이터 재현 시험 (SCR-F04)
}.items()}
# 테넌트에 속하지 않는 플랫폼 자원 — 테넌트 사용자는 역할이 있어도 불가
PLATFORM_ONLY = frozenset({"agent.register", "publisher", "governance", "redteam", "tenant.admin", "identity", "sandbox",
                           "quality.run"})


class AuthError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


# ── 비밀번호 ─────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(pw: str, stored: str | None) -> bool:
    if not stored:
        hashlib.scrypt(pw.encode(), salt=b"0" * 16, n=2**14, r=8, p=1, dklen=32)   # 계정 유무를 시간으로 드러내지 않는다
        return False
    _, n, r, p, salt, dk = stored.split("$")
    got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    return hmac.compare_digest(got, base64.b64decode(dk))


def validate_password(pw: str) -> None:
    if len(pw) < MIN_PASSWORD:
        raise AuthError(422, f"비밀번호는 {MIN_PASSWORD}자 이상")


# ── 토큰 ─────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _secret() -> bytes:
    """AUTH_SECRET 우선. 없으면 데이터 디렉터리에 생성·보관(로컬·리허설용). 운영은 외부 키 관리에서 주입."""
    raw = settings.auth_secret
    if raw and raw != "CHANGE_ME":
        return raw.encode()
    return kms.secret_file(Path(settings.auth_secret_file), lambda: secrets.token_urlsafe(48).encode())   # KMS 포장 저장(NFR-D2)


def _sign(sid: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(_secret(), sid.encode(), hashlib.sha256).digest()).decode().rstrip("=")


def token_of(sid: str) -> str:
    return f"am1.{sid}.{_sign(sid)}"


def _sid_of(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "am1" or not hmac.compare_digest(parts[2], _sign(parts[1])):
        return None
    return parts[1]


def issue(s: Session, user: models.User, kind: str = "session", name: str = "",
          ttl: timedelta | None = SESSION_TTL) -> tuple[models.AuthSession, str]:
    now = utcnow()
    row = models.AuthSession(id=secrets.token_hex(16), user_id=user.id, kind=kind, name=name[:120], created_at=now,
                             expires_at=now + ttl if ttl else None, last_seen_at=now)
    s.add(row)
    s.flush()
    return row, token_of(row.id)


def resolve(s: Session, token: str) -> tuple[models.AuthSession, models.User]:
    """토큰 → (세션, 사용자). 서명·회수·만료·유휴·계정 상태를 모두 본다."""
    sid = _sid_of(token)
    hit = s.execute(select(models.AuthSession, models.User).join(models.User, models.User.id == models.AuthSession.user_id)
                    .where(models.AuthSession.id == sid)).first() if sid else None     # 세션·사용자 한 번에
    row = hit[0] if hit else None
    if row is None or row.kind == "bootstrap" or row.revoked_at is not None:
        raise AuthError(401, "인증 필요 — 유효하지 않거나 회수된 토큰")
    now = utcnow()
    if row.expires_at and _utc(row.expires_at) <= now:
        raise AuthError(401, "세션 만료 — 다시 로그인")
    if row.kind == "session" and row.last_seen_at and now - _utc(row.last_seen_at) > SESSION_IDLE:
        row.revoked_at = now
        s.commit()
        raise AuthError(401, "유휴 30분 초과 — 다시 로그인")
    user = hit[1]
    if user is None or not user.active:
        raise AuthError(401, "비활성 계정")
    if not row.last_seen_at or now - _utc(row.last_seen_at) > timedelta(seconds=30):
        row.last_seen_at = now                     # 유휴 판정용 — 30초 단위로만 기록
    return row, user


def verify_login(s: Session, username: str, password: str) -> models.User:
    """1단계(비밀번호) 확인 — 실패 횟수·잠금(5회 → 15분)·원장. 세션은 만들지 않는다(2단계가 있으면 그 뒤에)."""
    user = s.scalars(select(models.User).where(models.User.username == username.strip().lower())).first()
    now = utcnow()
    if user is not None and user.locked_until and _utc(user.locked_until) > now:
        raise AuthError(423, f"로그인 {LOCK_AFTER}회 실패로 잠김 — {_utc(user.locked_until).isoformat(timespec='seconds')} 까지")
    if user is None or not user.active or user.kind != "human" or not check_password(password, user.password_hash):
        if user is not None:
            user.failed_logins += 1
            event = "login_failed"
            if user.failed_logins >= LOCK_AFTER:
                user.locked_until, user.failed_logins, event = now + LOCK_FOR, 0, "locked"
            ledger.append(s, "auth", user.id, {"event": event, "user": user.username}, home_chain(user))
            s.commit()
        raise AuthError(401, "아이디 또는 비밀번호가 올바르지 않다")
    return user


def start_session(s: Session, user: models.User, agent: str = "", mfa: str = "none") -> tuple[str, models.AuthSession]:
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, utcnow()
    row, token = issue(s, user, "session", agent)
    ledger.append(s, "auth", user.id, {"event": "login", "user": user.username, "session": row.id, "mfa": mfa,
                                       "breakGlass": user.break_glass}, home_chain(user))
    return token, row


def login(s: Session, username: str, password: str, agent: str = "") -> tuple[models.User, str, models.AuthSession]:
    user = verify_login(s, username, password)
    token, row = start_session(s, user, agent)
    return user, token, row


def home_chain(user: models.User) -> str:
    return user.tenant or ledger.PLATFORM


# ── 인가 ─────────────────────────────────────────────────────
def permissions(user: models.User) -> set[str]:
    roles = set(user.roles)
    return {p for p, allowed in PERMS.items() if roles & allowed and not (user.tenant and p in PLATFORM_ONLY)}


@dataclass
class Ctx:
    """요청 주체 — 사용자·권한·테넌트 범위. scope '*' = 모든 테넌트(플랫폼 사용자만)."""
    user: models.User
    scope: str
    perms: set[str] = field(default_factory=set)
    session_id: str | None = None
    session_row: models.AuthSession | None = field(default=None, repr=False)   # resolve 가 읽은 행 — 같은 요청에서 다시 조회하지 않게

    @property
    def name(self) -> str:
        return self.user.username

    @property
    def platform(self) -> bool:
        return self.user.tenant is None

    def need(self, perm: str) -> Ctx:
        if perm not in self.perms:
            raise AuthError(403, f"권한 없음: {perm} (역할 {', '.join(self.user.roles)})")
        return self

    def tenant_for(self, requested: str | None) -> str:
        """쓰기 대상 테넌트. 범위가 정해진 주체가 다른 테넌트를 지정하면 403(교차 접근 차단)."""
        if self.scope != "*":
            if requested and requested != self.scope:
                raise AuthError(403, f"교차 테넌트 접근 차단: {self.scope} → {requested}")
            return self.scope
        return requested or "default"

    def read_filter(self, requested: str | None) -> str | None:
        """조회 필터 테넌트 (None = 전체, 플랫폼 범위만)."""
        if self.scope != "*":
            if requested and requested != self.scope:
                raise AuthError(403, f"교차 테넌트 접근 차단: {self.scope} → {requested}")
            return self.scope
        return requested

    def visible(self, tenant: str) -> bool:
        return self.scope in ("*", tenant)


def _svid_user(s: Session, token: str) -> models.User:
    """JWT-SVID 로 호출한 서비스 계정 (정적 API 키 대신 1시간 워크로드 신원)."""
    from app import identity
    try:
        claims = identity.verify(s, token)
    except identity.IdentityError as exc:
        raise AuthError(exc.status, exc.msg) from exc
    wid = s.get(models.WorkloadIdentity, claims["sub"])
    if wid.kind != "service":
        raise AuthError(403, "에이전트·플랫폼 SVID 는 API 주체가 아니다 — 서비스 계정 SVID 만")
    user = s.scalars(select(models.User).where(models.User.username == wid.ref)).first()
    if user is None or not user.active:
        raise AuthError(401, "비활성 서비스 계정")
    return user


def context(s: Session, token: str, requested_tenant: str | None) -> Ctx:
    if token.startswith("eyJ") and token.count(".") == 2:
        user = _svid_user(s, token)
        return Ctx(user=user, scope=user.tenant or requested_tenant or "*", perms=permissions(user), session_id=None)
    row, user = resolve(s, token)
    if user.tenant is not None:
        if requested_tenant and requested_tenant not in ("*", user.tenant):
            raise AuthError(403, f"교차 테넌트 접근 차단: {user.tenant} → {requested_tenant}")
        scope = user.tenant
    else:
        scope = requested_tenant or "*"
        if scope != "*" and s.get(models.Tenant, scope) is None:
            raise AuthError(404, f"tenant {scope} 없음")
    return Ctx(user=user, scope=scope, perms=permissions(user), session_id=row.id, session_row=row)


def check(user: models.User, perm: str, tenant: str | None) -> dict:
    """권한 확인 질의 (SCR-R02 '이 사용자가 이 동작을 할 수 있는가') — 허용/거부와 근거."""
    if perm not in PERMS:
        return {"allowed": False, "reason": f"알 수 없는 동작 {perm}"}
    if not user.active:
        return {"allowed": False, "reason": "비활성 계정"}
    roles = sorted(set(user.roles) & PERMS[perm])
    if not roles:
        return {"allowed": False, "reason": f"{perm} 를 가진 역할 없음 (보유 {', '.join(user.roles)})"}
    if user.tenant and perm in PLATFORM_ONLY:
        return {"allowed": False, "reason": f"{perm} 는 플랫폼 사용자 전용 (사용자 테넌트 {user.tenant})"}
    if user.tenant and tenant and tenant != user.tenant:
        return {"allowed": False, "reason": f"교차 테넌트 — 사용자 {user.tenant}, 대상 {tenant}"}
    return {"allowed": True, "reason": f"역할 {', '.join(roles)} → {perm}" + (f" @ {user.tenant or '모든 테넌트'}")}


# ── 사용자 관리 ───────────────────────────────────────────────
def out(u: models.User) -> dict:
    return {"id": u.id, "username": u.username, "displayName": u.display_name, "roles": u.roles, "tenant": u.tenant,
            "kind": u.kind, "active": u.active, "breakGlass": u.break_glass,
            "locked": bool(u.locked_until and _utc(u.locked_until) > utcnow()),
            "lastLoginAt": u.last_login_at.isoformat() if u.last_login_at else None,
            "createdAt": u.created_at.isoformat() if u.created_at else None, "createdBy": u.created_by}


def _check_roles(actor: Ctx | None, roles: list[str], tenant: str | None) -> None:
    bad = [r for r in roles if r not in ROLES]
    if bad or not roles:
        raise AuthError(422, f"알 수 없는 역할 {bad}" if bad else "역할 1개 이상")
    if tenant is not None and "platform_admin" in roles:
        raise AuthError(422, "플랫폼 관리자는 테넌트에 속할 수 없다")
    if actor is not None and not actor.platform and "platform_admin" in roles:
        raise AuthError(403, "테넌트 관리자는 플랫폼 관리자를 부여할 수 없다")


def create_user(s: Session, actor: Ctx | None, username: str, display_name: str, roles: list[str],
                tenant: str | None, password: str | None = None, kind: str = "human",
                break_glass: bool = False) -> models.User:
    username = username.strip().lower()
    if not USERNAME.match(username):
        raise AuthError(422, "사용자 ID 는 소문자·숫자·._@- 3~64자")
    if actor is not None and not actor.platform:
        if tenant and tenant != actor.user.tenant:
            raise AuthError(403, f"교차 테넌트 접근 차단: {actor.user.tenant} → {tenant}")
        tenant = actor.user.tenant                       # 테넌트 관리자는 자기 테넌트에만 만든다
    if tenant is not None and s.get(models.Tenant, tenant) is None:
        raise AuthError(404, f"tenant {tenant} 없음")
    if kind == "service":
        roles, password = ["service"], None
    _check_roles(actor, roles, tenant)
    if kind == "human":
        if not password:
            raise AuthError(422, "비밀번호 필요")
        validate_password(password)
    if s.scalars(select(models.User).where(models.User.username == username)).first():
        raise AuthError(409, f"사용자 {username} 이미 있음")
    u = models.User(id=f"usr_{secrets.token_hex(6)}", username=username, display_name=display_name or username,
                    password_hash=hash_password(password) if password else None, roles=sorted(set(roles)),
                    tenant=tenant, kind=kind, active=True, break_glass=break_glass, failed_logins=0,
                    created_by=actor.name if actor else "bootstrap", created_at=utcnow())
    s.add(u)
    s.flush()
    ledger.append(s, "auth", u.id, {"event": "user_created", "user": u.username, "roles": u.roles, "kind": kind,
                                    "tenant": tenant, "breakGlass": break_glass,
                                    "by": actor.name if actor else "bootstrap"}, home_chain(u))
    return u


def update_user(s: Session, actor: Ctx, u: models.User, roles: list[str] | None = None, active: bool | None = None,
                display_name: str | None = None, password: str | None = None) -> models.User:
    if not actor.platform and u.tenant != actor.user.tenant:
        raise AuthError(404, f"user {u.id} 없음")
    changes: dict = {}
    if roles is not None and sorted(set(roles)) != sorted(u.roles):
        if u.id == actor.user.id:
            raise AuthError(403, "자기 역할은 바꿀 수 없다 (자기 권한 상향 금지)")
        _check_roles(actor, roles, u.tenant)
        changes["roles"] = {"from": u.roles, "to": sorted(set(roles))}
        u.roles = sorted(set(roles))
    if active is not None and active != u.active:
        if u.id == actor.user.id and not active:
            raise AuthError(403, "자기 계정은 비활성화할 수 없다")
        changes["active"] = active
        u.active = active
        if not active:
            revoke_all(s, u)
    if display_name:
        u.display_name = display_name
    if password:
        validate_password(password)
        u.password_hash, u.failed_logins, u.locked_until = hash_password(password), 0, None
        changes["password"] = "reset"
        revoke_all(s, u)
    if changes:
        ledger.append(s, "auth", u.id, {"event": "user_updated", "user": u.username, "changes": changes,
                                        "by": actor.name}, home_chain(u))
    return u


def revoke_all(s: Session, u: models.User) -> int:
    rows = list(s.scalars(select(models.AuthSession).where(models.AuthSession.user_id == u.id,
                                                           models.AuthSession.revoked_at.is_(None))))
    for r in rows:
        r.revoked_at = utcnow()
    return len(rows)


def session_out(r: models.AuthSession, current: str | None = None) -> dict:
    now = utcnow()
    state = ("revoked" if r.revoked_at else "expired" if r.expires_at and _utc(r.expires_at) <= now
             else "idle" if r.kind == "session" and r.last_seen_at and now - _utc(r.last_seen_at) > SESSION_IDLE
             else "active")
    if state == "active" and r.state == "review":
        state = "review"
    return {"id": r.id, "kind": r.kind, "name": r.name, "state": state, "current": r.id == current,
            "device": r.device, "location": r.location, "geo": r.geo, "dpop": bool(r.jkt), "mfa": r.mfa, "reviewReason": r.review_reason,
            "createdAt": r.created_at.isoformat(), "lastSeenAt": r.last_seen_at.isoformat() if r.last_seen_at else None,
            "expiresAt": r.expires_at.isoformat() if r.expires_at else None}


# ── 부트스트랩 (SCR-A06) ──────────────────────────────────────
BOOTSTRAP_ID = "bootstrap"


def has_admin(s: Session) -> bool:
    users = s.scalars(select(models.User).where(models.User.active.is_(True), models.User.tenant.is_(None)))
    return any("platform_admin" in u.roles for u in users)


def bootstrap_required(s: Session) -> bool:
    return not has_admin(s)


def bootstrap_valid(s: Session) -> bool:
    row = s.get(models.AuthSession, BOOTSTRAP_ID)
    return bool(row and row.revoked_at is None and row.expires_at and _utc(row.expires_at) > utcnow())


def issue_bootstrap(s: Session, force: bool = False, keep_valid: bool = False) -> str | None:
    """1회용 부트스트랩 토큰(24h). 관리자가 있으면 force(= aegis admin reset, break-glass 재발급)일 때만.
    keep_valid 면 유효한 토큰이 있을 때 재발급하지 않는다(API 워커 여러 개가 동시에 기동). 원문은 반환 1회 — DB 에는 해시만."""
    if has_admin(s) and not force:
        return None
    if keep_valid and bootstrap_valid(s):
        return None
    token = f"aegis-boot-{secrets.token_urlsafe(18)}"
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = s.get(models.AuthSession, BOOTSTRAP_ID)
    now = utcnow()
    if row is None:
        row = models.AuthSession(id=BOOTSTRAP_ID, kind="bootstrap", user_id=None, created_at=now)
        s.add(row)
    row.name, row.expires_at, row.revoked_at, row.last_seen_at = digest, now + BOOTSTRAP_TTL, None, None
    ledger.append(s, "auth", BOOTSTRAP_ID, {"event": "bootstrap_issued", "force": force,
                                            "expiresAt": row.expires_at.isoformat()})
    return token


def use_bootstrap(s: Session, token: str) -> None:
    row = s.get(models.AuthSession, BOOTSTRAP_ID)
    now = utcnow()
    ok = (row is not None and row.revoked_at is None and row.expires_at and _utc(row.expires_at) > now
          and hmac.compare_digest(row.name, hashlib.sha256(token.encode()).hexdigest()))
    if not ok:
        raise AuthError(401, "부트스트랩 토큰이 없거나 만료·사용됨 — make admin-token 으로 재발급")
    row.revoked_at = now                              # 사용 즉시 폐기


def user_count(s: Session) -> int:
    return s.scalar(select(func.count()).select_from(models.User)) or 0
