"""workload identity and dynamic secrets (FR-P07, SCR-R03) — SPIFFE JWT-SVID 발급·회전 기록, 동적 시크릿 임대.

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workload_identities",
        sa.Column("spiffe_id", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=10), nullable=False),
        sa.Column("ref", sa.String(length=64), nullable=False),
        sa.Column("tenant", sa.String(length=32), nullable=True),
        sa.Column("ttl_sec", sa.Integer(), nullable=False),
        sa.Column("jti", sa.String(length=32), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotations", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("spiffe_id"),
    )
    op.create_index("ix_workload_identities_ref", "workload_identities", ["ref"])
    op.create_table(
        "secret_leases",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant", sa.String(length=32), nullable=False),
        sa.Column("path", sa.String(length=120), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("holder", sa.String(length=200), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("renewals", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("secret_hash"),
    )
    op.create_index("ix_secret_leases_tenant", "secret_leases", ["tenant"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON workload_identities, secret_leases TO aegis_app")
        op.execute("ALTER TABLE secret_leases ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE secret_leases FORCE ROW LEVEL SECURITY")
        op.execute("CREATE POLICY secret_leases_tenant ON secret_leases USING (aegis_tenant_visible(tenant)) "
                   "WITH CHECK (aegis_tenant_visible(tenant))")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS secret_leases_tenant ON secret_leases")
    op.drop_index("ix_secret_leases_tenant", table_name="secret_leases")
    op.drop_table("secret_leases")
    op.drop_index("ix_workload_identities_ref", table_name="workload_identities")
    op.drop_table("workload_identities")
