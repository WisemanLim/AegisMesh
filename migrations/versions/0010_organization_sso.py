"""organization SSO (FR-D5-01·03, SCR-A06·B02) — OIDC 설정, IdP 그룹→역할 매핑, 인가 요청(PKCE), 외부 신원 연결.

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sso_config",
        sa.Column("id", sa.String(length=16), nullable=False),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("client_id", sa.String(length=120), nullable=False),
        sa.Column("groups_claim", sa.String(length=64), nullable=False),
        sa.Column("mfa_required", sa.Boolean(), nullable=False),
        sa.Column("acr_values", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "sso_group_maps",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("group", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("tenant", sa.String(length=32), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sso_group_maps_group", "sso_group_maps", ["group"])
    op.create_table(
        "oidc_requests",
        sa.Column("state", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("verifier", sa.String(length=128), nullable=False),
        sa.Column("redirect_uri", sa.String(length=255), nullable=False),
        sa.Column("next", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("state"),
    )
    op.add_column("users", sa.Column("external_id", sa.String(length=255), nullable=True))
    op.create_index("ix_users_external_id", "users", ["external_id"], unique=True)
    if op.get_bind().dialect.name == "postgresql":
        op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON sso_config, sso_group_maps, oidc_requests TO aegis_app")
        op.execute("GRANT USAGE, SELECT ON SEQUENCE sso_group_maps_id_seq TO aegis_app")


def downgrade() -> None:
    op.drop_index("ix_users_external_id", table_name="users")
    with op.batch_alter_table("users") as b:
        b.drop_column("external_id")
    op.drop_table("oidc_requests")
    op.drop_index("ix_sso_group_maps_group", table_name="sso_group_maps")
    op.drop_table("sso_group_maps")
    op.drop_table("sso_config")
