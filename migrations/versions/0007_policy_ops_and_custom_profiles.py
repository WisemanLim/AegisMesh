"""policy ops and custom profiles (FR-P02, SCR-D03·D04·C08) — 승인 연계 행동(정책 롤백 등), 테넌트 사용자 정의 프로파일.

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("action", sa.JSON(), nullable=True))
    op.add_column("profiles", sa.Column("tenant", sa.String(length=32), nullable=True))
    op.add_column("profiles", sa.Column("created_by", sa.String(length=64), nullable=True))
    op.create_index("ix_profiles_tenant", "profiles", ["tenant"])


def downgrade() -> None:
    with op.batch_alter_table("profiles") as b:
        b.drop_index("ix_profiles_tenant")
        b.drop_column("created_by")
        b.drop_column("tenant")
    with op.batch_alter_table("approvals") as b:
        b.drop_column("action")
