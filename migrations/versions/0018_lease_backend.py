"""secret lease backend (Epic 41) — 임대 발급 엔진(builtin|openbao)·OpenBao 토큰 접근자(accessor).

Revision ID: 0018
Revises: 0017
"""
import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("secret_leases") as b:
        b.add_column(sa.Column("backend", sa.String(16), nullable=False, server_default="builtin"))
        b.add_column(sa.Column("accessor", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("secret_leases") as b:
        b.drop_column("accessor")
        b.drop_column("backend")
