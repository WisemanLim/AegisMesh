"""공통 의존성 — DB 세션, 인증 주체·권한·테넌트 범위 (SCR-B02·R02, FR-P13)."""
from collections.abc import Callable, Iterator

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app import auth, db, evidence_writer, mfa, models, tenancy
from app.auth import Ctx

INLINE = frozenset({"/v1/judge", "/v1/judge:batch", "/v1/judge:stream"})   # 증적 비동기 적재 경로(NFR-L5)


def session(request: Request) -> Iterator[Session]:
    if request.url.path not in INLINE:
        evidence_writer.flush()                       # 읽기 일관성 — 이 프로세스의 대기 증적을 먼저 적재
    with db.SessionLocal() as s:
        yield s


def ctx(request: Request, s: Session = Depends(session), authorization: str | None = Header(None),
        x_aegis_tenant: str | None = Header(None), dpop: str | None = Header(None)) -> Ctx:
    """Authorization: Bearer am1.… → 주체. X-Aegis-Tenant 로 플랫폼 사용자가 테넌트 범위를 고른다.
    범위는 앱 계층 필터와 PostgreSQL RLS(aegis.tenant) 둘 다에 적용된다."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "인증 필요 (Authorization: Bearer)", headers={"WWW-Authenticate": "Bearer"})
    try:
        c = auth.context(s, token.strip(), x_aegis_tenant)
        if c.session_id:                     # SCR-B02·FR-D5-03 — DPoP 소유 증명·새 기기·위치 재인증·탈취 토큰 재사용
            mfa.enforce(s, c.session_row or s.get(models.AuthSession, c.session_id), c.user, request, token.strip(), dpop)
    except auth.AuthError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    db.set_scope(s, c.scope)         # 이 트랜잭션에 바로 적용(set_config 지역) — 다음 트랜잭션은 after_begin 이 다시 건다
    if s.new or s.dirty or s.deleted:
        s.commit()                   # 쓴 것(최근 사용 시각 30초 단위·DPoP jti·원장)이 있을 때만 — 매 요청 커밋·만료 재조회를 없앤다(NFR-P1, Epic 66)
    return c


def principal(c: Ctx = Depends(ctx)) -> str:
    return c.name


def platform_scope(s: Session, c: Ctx) -> None:
    """플랫폼 자원(에이전트·게시자·거버넌스·테넌트·사용자)은 테넌트 범위 밖 — 플랫폼 주체만 '*' 로 넓힌다."""
    if c.platform:
        c.scope = "*"
        db.set_scope(s, "*")


def need(perm: str) -> Callable[..., Ctx]:
    def dep(s: Session = Depends(session), c: Ctx = Depends(ctx)) -> Ctx:
        try:
            c.need(perm)
        except auth.AuthError as exc:
            raise HTTPException(exc.status, exc.msg) from exc
        if perm in auth.PLATFORM_ONLY or perm == "user.admin":
            platform_scope(s, c)
        return c
    return dep


def write_tenant(s: Session, c: Ctx, requested: str | None, cached: bool = False) -> str:
    """쓰기 대상 테넌트 — 범위 밖이면 403, 없는·비활성 테넌트면 404/409. cached = 인라인 판정 경로(짧은 TTL 캐시)."""
    try:
        tenant = c.tenant_for(requested)
        tenancy.require(s, tenant, cached)
    except auth.AuthError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    except tenancy.TenantError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    return tenant


def read_tenant(c: Ctx, requested: str | None) -> str | None:
    try:
        return c.read_filter(requested)
    except auth.AuthError as exc:
        raise HTTPException(exc.status, exc.msg) from exc


def visible_or_404(c: Ctx, row, what: str):
    """없는 자원과 다른 테넌트 자원을 구분하지 않는다(존재 자체를 드러내지 않음)."""
    if row is None or not c.visible(row.tenant):
        raise HTTPException(404, f"{what} 없음")
    return row
