"""session geo (Epic 55) — 지오 IP 표시(나라·도시)·좌표·그 지점에서 마지막으로 본 시각. 새 위치·불가능한 이동 판단 근거.

Revision ID: 0021
Revises: 0020
"""
import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("auth_sessions") as b:
        b.add_column(sa.Column("geo", sa.String(80), nullable=True))
        b.add_column(sa.Column("geo_lat", sa.Float(), nullable=True))
        b.add_column(sa.Column("geo_lon", sa.Float(), nullable=True))
        b.add_column(sa.Column("geo_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("auth_sessions") as b:
        for c in ("geo_at", "geo_lon", "geo_lat", "geo"):
            b.drop_column(c)
