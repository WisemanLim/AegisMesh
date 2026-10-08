"""quality labels (NFR-Q1·Q2·Q6, SCR-O02·Q04) — 판정 이의·라벨(오탐 확정), 이의에서 편입된 골든 표본.

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None
TABLES = ("finding_labels", "golden_samples")


def upgrade() -> None:
    op.create_table(
        "finding_labels",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("tenant", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=8), nullable=False),
        sa.Column("gate", sa.String(length=8), nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rule_id", sa.String(length=80), nullable=False),
        sa.Column("reason", sa.String(length=20), nullable=False),
        sa.Column("detail", sa.String(length=500), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("label", sa.String(length=4), nullable=True),
        sa.Column("rejudge", sa.JSON(), nullable=True),
        sa.Column("sample_id", sa.String(length=32), nullable=True),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(length=64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.String(length=300), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_labels_finding_id", "finding_labels", ["finding_id"])
    op.create_index("ix_finding_labels_tenant", "finding_labels", ["tenant"])
    op.create_index("ix_finding_labels_agent_id", "finding_labels", ["agent_id"])
    op.create_index("ix_finding_labels_decided_at", "finding_labels", ["decided_at"])
    op.create_table(
        "golden_samples",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant", sa.String(length=64), nullable=False),
        sa.Column("gate", sa.String(length=8), nullable=False),
        sa.Column("agent_id", sa.String(length=8), nullable=True),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_golden_samples_tenant", "golden_samples", ["tenant"])
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
    op.drop_table("golden_samples")
    op.drop_table("finding_labels")
