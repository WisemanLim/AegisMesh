"""aegismesh — DB 엔진 (SQLite / PostgreSQL / MySQL / MariaDB 공용, DATABASE_URL 로 결정)."""
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _make_engine():
    url = settings.database_url
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True, pool_size=settings.db_pool_size, max_overflow=settings.db_max_overflow)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False)

# ── 테넌트 범위 (FR-P13) ─────────────────────────────────────────
# 앱 계층: API 가 요청 주체의 범위로 모든 질의를 거른다(app/api/deps.py).
# DB 계층(PostgreSQL): 연결은 비특권 역할 aegis_app 으로 SET ROLE 하고, 트랜잭션마다 aegis.tenant 를 설정해 RLS 가 거른다.
# 범위 미설정 세션은 '' → 테넌트 행이 보이지 않는다(실패 시 닫힘). worker·seed 등 시스템 작업만 SYSTEM('*') 을 쓴다.
APP_ROLE = "aegis_app"
SYSTEM = {"tenant_scope": "*"}


def system_session() -> Session:
    return SessionLocal(info=dict(SYSTEM))


def set_scope(s: Session, scope: str) -> None:
    """현재 트랜잭션과 이후 트랜잭션의 테넌트 범위를 바꾼다."""
    s.info["tenant_scope"] = scope
    if s.in_transaction() and s.get_bind().dialect.name == "postgresql":
        s.execute(text("SELECT set_config('aegis.tenant', :t, true)"), {"t": scope})


@event.listens_for(SessionLocal, "after_begin")
def _apply_scope(session: Session, _transaction, connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.execute(text("SELECT set_config('aegis.tenant', :t, true)"),
                           {"t": session.info.get("tenant_scope", "")})


if engine.dialect.name == "postgresql":
    @event.listens_for(engine, "checkout")
    def _app_role(dbapi_conn, record, _proxy) -> None:
        """RLS 는 슈퍼유저·소유자에게 적용되지 않는다 → 0006 이 만든 비특권 역할로 전환.
        역할이 아직 없으면(마이그레이션 전) 다음 체크아웃에서 다시 확인 — 마이그레이션 후 재기동 없이도 풀 연결이 전환된다."""
        if record.info.get("app_role"):
            return
        with dbapi_conn.cursor() as c:
            c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (APP_ROLE,))
            if c.fetchone():
                c.execute(f"SET ROLE {APP_ROLE}")
                record.info["app_role"] = True
        dbapi_conn.commit()

    @event.listens_for(SessionLocal, "after_flush")
    def _ledger_sync_commit(session: Session, _ctx) -> None:
        """원장 RPO 0 (NFR-A5) — 증적을 쓴 트랜잭션만 동기 대기 서버 플러시까지 커밋을 기다린다.
        주 서버 기본값은 synchronous_commit=local(docker-compose.prod.yml). 동기 대기 서버가 없으면 on 은 로컬 플러시와 같다.
        after_flush 시점의 session.new 는 아직 flush 전 목록이다."""
        if any(getattr(o, "__tablename__", None) == "evidence" for o in session.new):
            session.connection().exec_driver_sql("SET LOCAL synchronous_commit TO on")


def ping() -> bool:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True
