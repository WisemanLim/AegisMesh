"""incident totals (NFR-P1·L5) — 사건 행에 최근 ID 만 남기고 총계를 따로 센다(반복 공격 시 행 크기·갱신 비용 고정).

Revision ID: 0011
Revises: 0010
"""
import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("finding_total", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("incidents", sa.Column("trace_total", sa.Integer(), nullable=False, server_default="0"))
    op.execute("UPDATE incidents SET finding_total = json_array_length(finding_ids), trace_total = json_array_length(trace_ids)")


def downgrade() -> None:
    with op.batch_alter_table("incidents") as b:
        b.drop_column("trace_total")
        b.drop_column("finding_total")
