"""Alembic env — DATABASE_URL(설정) 사용, 모델 메타데이터 자동 감지."""
from alembic import context

from app import models  # noqa: F401 — 메타데이터 등록
from app.db import Base, engine

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=str(engine.url), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            # 앱 연결은 비특권 역할(aegis_app)로 SET ROLE 한다(app/db.py) — 마이그레이션은 소유자로, 전 테넌트 범위로.
            connection.exec_driver_sql("RESET ROLE")
            connection.exec_driver_sql("SELECT set_config('aegis.tenant', '*', false)")
            connection.commit()
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=engine.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()
        if connection.dialect.name == "postgresql":
            connection.invalidate()          # 역할을 되돌린 연결을 풀에 돌려주지 않는다


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
