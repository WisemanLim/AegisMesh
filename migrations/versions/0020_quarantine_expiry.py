"""quarantine expiry (Epic 51) — 깊은 검사 경보로 만든 주체·세션 격리의 기한. 비우면 무기한(기존 상시 점검 격리).

Revision ID: 0020
Revises: 0019
"""
import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("quarantine") as b:
        b.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("quarantine") as b:
        b.drop_column("expires_at")
