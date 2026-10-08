"""bus cursor (Epic 60) — 발견 버스(NATS JetStream) 중계 커서: 원장 seq 를 어디까지 게시했는지(확인 받은 곳까지만 전진).

Revision ID: 0023
Revises: 0022
"""
import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("bus_cursors", sa.Column("name", sa.String(length=32), nullable=False), sa.Column("seq", sa.Integer(), nullable=False),
                    sa.PrimaryKeyConstraint("name"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute("GRANT SELECT, INSERT, UPDATE ON bus_cursors TO aegis_app")


def downgrade() -> None:
    op.drop_table("bus_cursors")
