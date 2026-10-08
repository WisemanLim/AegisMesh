"""tenant auth policy (OQ3 결정) — 2단계 강제 범위(privileged|all)·인증기(AAGUID) 허용목록.

Revision ID: 0017
Revises: 0016
"""
import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("tenants") as b:
        b.add_column(sa.Column("auth_policy", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("tenants") as b:
        b.drop_column("auth_policy")
