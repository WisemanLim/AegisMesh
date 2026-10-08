"""airgap and marketplace (FR-P14, NFR-C3, SCR-A05·R05·C10) — 내부 신뢰 저장소, 번들 반입 기록, 장터 목록.

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trust_keys",
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("added_by", sa.String(length=64), nullable=False),
        sa.Column("approval_id", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("key_id"),
    )
    op.create_table(
        "bundle_imports",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=12), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("applied", sa.JSON(), nullable=False),
        sa.Column("imported_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "market_listings",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("agent_id", sa.String(length=8), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("name_ko", sa.String(length=120), nullable=False),
        sa.Column("item_id", sa.String(length=8), nullable=False),
        sa.Column("publisher", sa.String(length=64), nullable=True),
        sa.Column("tier", sa.String(length=10), nullable=False),
        sa.Column("license", sa.String(length=120), nullable=False),
        sa.Column("isolation", sa.String(length=2), nullable=False),
        sa.Column("bundle", sa.JSON(), nullable=False),
        sa.Column("bundle_sha256", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=12), nullable=False),
        sa.Column("review_id", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("publisher_keys", sa.Column("tier", sa.String(length=10), nullable=False, server_default="community"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON trust_keys, bundle_imports, market_listings TO aegis_app")


def downgrade() -> None:
    with op.batch_alter_table("publisher_keys") as b:
        b.drop_column("tier")
    op.drop_table("market_listings")
    op.drop_table("bundle_imports")
    op.drop_table("trust_keys")
