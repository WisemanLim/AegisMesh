"""traffic samples (OQ1 · NFR-D1 · SCR-C06) — 미리보기용 실제 트래픽 마스킹 표본(테넌트 옵트인·2인 승인·N건·기한).

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None
TABLES = ("traffic_samples",)


def upgrade() -> None:
    op.create_table(
        "traffic_samples",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant", sa.String(length=64), nullable=False),
        sa.Column("gate", sa.String(length=10), nullable=False),
        sa.Column("target", sa.String(length=120), nullable=True),
        sa.Column("profile", sa.String(length=64), nullable=True),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("masked", sa.JSON(), nullable=False),
        sa.Column("label", sa.String(length=8), nullable=True),
        sa.Column("labeled_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_traffic_samples_tenant", "traffic_samples", ["tenant"])
    op.create_index("ix_traffic_samples_expires_at", "traffic_samples", ["expires_at"])
    with op.batch_alter_table("tenants") as b:
        b.add_column(sa.Column("sample_retention", sa.JSON(), nullable=True))
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
    with op.batch_alter_table("tenants") as b:
        b.drop_column("sample_retention")
    op.drop_index("ix_traffic_samples_expires_at", table_name="traffic_samples")
    op.drop_index("ix_traffic_samples_tenant", table_name="traffic_samples")
    op.drop_table("traffic_samples")
