"""login hardening (SCR-B02 · FR-D5-03) — 패스키(WebAuthn)·인증 앱 OTP 2단계, DPoP 세션 바인딩, 새 기기·위치 재인증.

Revision ID: 0014
Revises: 0013
"""
import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None
TABLES = ("webauthn_credentials", "mfa_challenges", "dpop_jti")


def upgrade() -> None:
    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("user_id", sa.String(length=32), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("alg", sa.String(length=8), nullable=False),
        sa.Column("aaguid", sa.String(length=32), nullable=True),
        sa.Column("transports", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webauthn_credentials_user_id", "webauthn_credentials", ["user_id"])
    op.create_table(
        "mfa_challenges",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("purpose", sa.String(length=12), nullable=False),
        sa.Column("challenge", sa.String(length=128), nullable=False),
        sa.Column("jkt", sa.String(length=64), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_mfa_challenges_user_id", "mfa_challenges", ["user_id"])
    op.create_table(
        "dpop_jti",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dpop_jti_seen_at", "dpop_jti", ["seen_at"])
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("totp_secret", sa.String(length=255), nullable=True))
        b.add_column(sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("totp_last_step", sa.Integer(), nullable=True))
    with op.batch_alter_table("auth_sessions") as b:
        b.add_column(sa.Column("jkt", sa.String(length=64), nullable=True))
        b.add_column(sa.Column("mfa", sa.String(length=16), nullable=True))
        b.add_column(sa.Column("device", sa.String(length=120), nullable=True))
        b.add_column(sa.Column("device_hash", sa.String(length=16), nullable=True))
        b.add_column(sa.Column("location", sa.String(length=64), nullable=True))
        b.add_column(sa.Column("state", sa.String(length=12), nullable=False, server_default="ok"))
        b.add_column(sa.Column("review_reason", sa.String(length=200), nullable=True))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(TABLES)} TO aegis_app")


def downgrade() -> None:
    with op.batch_alter_table("auth_sessions") as b:
        for c in ("review_reason", "state", "location", "device_hash", "device", "mfa", "jkt"):
            b.drop_column(c)
    with op.batch_alter_table("users") as b:
        for c in ("totp_last_step", "totp_enabled", "totp_secret"):
            b.drop_column(c)
    op.drop_index("ix_dpop_jti_seen_at", table_name="dpop_jti")
    op.drop_table("dpop_jti")
    op.drop_index("ix_mfa_challenges_user_id", table_name="mfa_challenges")
    op.drop_table("mfa_challenges")
    op.drop_index("ix_webauthn_credentials_user_id", table_name="webauthn_credentials")
    op.drop_table("webauthn_credentials")
