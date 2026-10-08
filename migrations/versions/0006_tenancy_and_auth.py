"""tenancy and auth (FR-P13, SCR-R01·R02·B02) — 테넌트·사용자·세션, 테넌트별 증적 체인·정책 네임스페이스,
PostgreSQL RLS(앱 계층 강제와 이중).

RLS 는 테이블 소유자·슈퍼유저에게 적용되지 않는다. 그래서 비특권 역할 aegis_app 을 만들고 앱 연결이 SET ROLE 한다
(app/db.py). 마이그레이션은 RESET ROLE 후 소유자로 실행한다(migrations/env.py).

Revision ID: 0006
Revises: 0005
"""
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

TENANT_TABLES = ("findings", "approvals", "evidence", "profile_applications", "scan_targets", "quarantine",
                 "incidents", "policies")
APP_ROLE = "aegis_app"


def _policies_with_tenant() -> None:
    """유일 제약 (policy_id, version) → (tenant, policy_id, version). 이름 없는 제약을 엔진 공통으로 바꾸려고
    새 표로 복사 후 교체(SQL 복사 — 엔진별 타입 변환 없이)."""
    op.create_table(
        "policies_v2",
        sa.Column("pk", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant", sa.String(length=32), nullable=False, server_default="default"),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("body", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("pk"),
        sa.UniqueConstraint("tenant", "policy_id", "version"),
    )
    op.execute("INSERT INTO policies_v2 (tenant, policy_id, version, body, created_by, created_at) "
               "SELECT 'default', policy_id, version, body, created_by, created_at FROM policies ORDER BY pk")
    op.drop_index("ix_policies_policy_id", table_name="policies")
    op.drop_table("policies")
    op.rename_table("policies_v2", "policies")
    op.create_index("ix_policies_policy_id", "policies", ["policy_id"])
    op.create_index("ix_policies_tenant", "policies", ["tenant"])


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    t = op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("isolation", sa.String(length=10), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("region", sa.String(length=16), nullable=False),
        sa.Column("lang", sa.String(length=2), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(t, [{"id": "default", "name": "기본 테넌트", "isolation": "logical", "retention_days": 90,
                        "region": "kr", "lang": "ko", "active": True, "created_by": "system", "created_at": now}])
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("tenant", sa.String(length=32), nullable=True),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("break_glass", sa.Boolean(), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_tenant", "users", ["tenant"])
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=True),
        sa.Column("kind", sa.String(length=12), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_table(
        "ledger_chains",
        sa.Column("chain", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("chain"),
    )
    # 추가 전용 테이블 — 열 추가는 UPDATE 트리거를 발화하지 않는다. 기존 레코드는 legacy 체인으로 동결.
    op.add_column("evidence", sa.Column("chain", sa.String(length=32), nullable=False, server_default="legacy"))
    op.create_index("ix_evidence_chain_seq", "evidence", ["chain", "seq"])
    op.add_column("ledger_checkpoints", sa.Column("chain", sa.String(length=32), nullable=False, server_default="legacy"))
    _policies_with_tenant()

    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"""DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    CREATE ROLE {APP_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
  END IF;
END $$""")
        op.execute(f"GRANT {APP_ROLE} TO CURRENT_USER")
        op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}")
        op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")
        op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}")
        op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE}")
        # 테넌트 범위: 트랜잭션 로컬 설정 aegis.tenant ('*' = 플랫폼). 미설정이면 아무 행도 보이지 않는다(실패 시 닫힘).
        op.execute("""CREATE OR REPLACE FUNCTION aegis_tenant_visible(t text) RETURNS boolean
LANGUAGE sql STABLE AS $$ SELECT coalesce(current_setting('aegis.tenant', true), '') IN ('*', t) $$""")
        for tbl in TENANT_TABLES:
            op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {tbl}_tenant ON {tbl} USING (aegis_tenant_visible(tenant)) "
                       f"WITH CHECK (aegis_tenant_visible(tenant))")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for tbl in TENANT_TABLES:
            op.execute(f"DROP POLICY IF EXISTS {tbl}_tenant ON {tbl}")
            op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY")
        op.execute("DROP FUNCTION IF EXISTS aegis_tenant_visible(text)")
    op.drop_index("ix_evidence_chain_seq", table_name="evidence")
    op.drop_table("ledger_chains")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_users_tenant", table_name="users")
    op.drop_table("users")
    op.drop_table("tenants")
    # evidence.chain·ledger_checkpoints.chain·policies.tenant 는 추가 전용 원장 보존을 위해 되돌리지 않는다.
