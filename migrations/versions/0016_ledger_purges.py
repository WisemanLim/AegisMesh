"""ledger retention purges (NFR-S · R07 · COMPLIANCE 추가 시험) — 보존기한 만료 삭제는 2인 승인 배치로만.

evidence 의 DELETE 는 여전히 막혀 있고, ledger_purges 에 승인된 구간(체인·through_seq)이 있을 때 그 구간 안의 행만 지울 수 있다.
ledger_purges 자체는 추가 전용(삭제 증명서 — 서명 포함).

Revision ID: 0016
Revises: 0015
"""
import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ledger_purges",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("chain", sa.String(length=32), nullable=False),
        sa.Column("through_seq", sa.Integer(), nullable=False),
        sa.Column("anchor_hash", sa.String(length=64), nullable=False),
        sa.Column("records", sa.Integer(), nullable=False),
        sa.Column("certificate", sa.JSON(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ledger_purges_chain", "ledger_purges", ["chain"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("GRANT SELECT, INSERT ON ledger_purges TO aegis_app")
        op.execute("""CREATE OR REPLACE FUNCTION aegis_evidence_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' AND EXISTS (SELECT 1 FROM ledger_purges p WHERE p.chain = OLD.chain AND OLD.seq <= p.through_seq) THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'append-only table: %', TG_TABLE_NAME;
END $$ LANGUAGE plpgsql""")
        op.execute("DROP TRIGGER IF EXISTS evidence_no_mutate ON evidence")
        op.execute("CREATE TRIGGER evidence_no_mutate BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION aegis_evidence_guard()")
        op.execute("CREATE TRIGGER ledger_purges_no_mutate BEFORE UPDATE OR DELETE ON ledger_purges FOR EACH ROW EXECUTE FUNCTION aegis_append_only()")
        op.execute("CREATE TRIGGER ledger_purges_no_truncate BEFORE TRUNCATE ON ledger_purges FOR EACH STATEMENT EXECUTE FUNCTION aegis_append_only()")
    else:
        op.execute("DROP TRIGGER IF EXISTS evidence_no_delete")
        op.execute("CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence "
                   "WHEN NOT EXISTS (SELECT 1 FROM ledger_purges p WHERE p.chain = OLD.chain AND OLD.seq <= p.through_seq) "
                   "BEGIN SELECT RAISE(ABORT, 'append-only table: evidence'); END")
        for ev in ("UPDATE", "DELETE"):
            op.execute(f"CREATE TRIGGER ledger_purges_no_{ev.lower()} BEFORE {ev} ON ledger_purges "
                       "BEGIN SELECT RAISE(ABORT, 'append-only table: ledger_purges'); END")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS ledger_purges_no_mutate ON ledger_purges")
        op.execute("DROP TRIGGER IF EXISTS ledger_purges_no_truncate ON ledger_purges")
        op.execute("DROP TRIGGER IF EXISTS evidence_no_mutate ON evidence")
        op.execute("CREATE TRIGGER evidence_no_mutate BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION aegis_append_only()")
        op.execute("DROP FUNCTION IF EXISTS aegis_evidence_guard()")
    else:
        for ev in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS ledger_purges_no_{ev}")
        op.execute("DROP TRIGGER IF EXISTS evidence_no_delete")
        op.execute("CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence BEGIN SELECT RAISE(ABORT, 'append-only table: evidence'); END")
    op.drop_index("ix_ledger_purges_chain", table_name="ledger_purges")
    op.drop_table("ledger_purges")
