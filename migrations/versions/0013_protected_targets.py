"""protected targets + approval expiry (SCR-C05·O06) — 즉시 사용 ② 보호 대상 등록, 승인 만료(만료 시 자동 거절).

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None
TABLES = ("protected_targets",)


def upgrade() -> None:
    op.create_table(
        "protected_targets",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("endpoint", sa.String(length=300), nullable=False),
        sa.Column("insertion", sa.String(length=16), nullable=False),
        sa.Column("model_provider", sa.String(length=200), nullable=False),
        sa.Column("external_model", sa.Boolean(), nullable=False),
        sa.Column("mcp_servers", sa.JSON(), nullable=False),
        sa.Column("egress", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant", "name"),
    )
    op.create_index("ix_protected_targets_tenant", "protected_targets", ["tenant"])
    op.add_column("approvals", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(TABLES)} TO aegis_app")
        for t in TABLES:
            op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {t}_tenant ON {t} USING (aegis_tenant_visible(tenant)) "
                       "WITH CHECK (aegis_tenant_visible(tenant))")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for t in TABLES:
            op.execute(f"DROP POLICY IF EXISTS {t}_tenant ON {t}")
    op.drop_column("approvals", "expires_at")
    op.drop_index("ix_protected_targets_tenant", table_name="protected_targets")
    op.drop_table("protected_targets")
