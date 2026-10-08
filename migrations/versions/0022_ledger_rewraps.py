"""ledger rewraps (Epic 57 · NFR-D2) — 암호화 전(0020 이전) 원장 기록의 저장 재암호화를 2인 승인 창 안에서만.

evidence 의 UPDATE 는 여전히 막혀 있고, 허용되는 갱신은 하나뿐이다: 승인된 ledger_rewraps 창(seq 구간·만료 시각) 안의 행을
평문 → 봉투 암호문({"_enc": …})으로 바꾸고 다른 열(seq·id·체인·종류·참조·테넌트·해시·이전 해시·시각)은 그대로인 갱신.
내용이 같은지는 해시 체인(평문 기준)이 보증한다 — 다른 값을 암호화해 넣으면 원장 검증이 깨진다.
ledger_rewraps 자체는 추가 전용(서명 증명서).

Revision ID: 0022
Revises: 0021
"""
import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

_PG_GUARD = """CREATE OR REPLACE FUNCTION aegis_evidence_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' AND EXISTS (SELECT 1 FROM ledger_purges p WHERE p.chain = OLD.chain AND OLD.seq <= p.through_seq) THEN
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE'
     AND NEW.seq = OLD.seq AND NEW.id = OLD.id AND NEW.chain = OLD.chain AND NEW.kind = OLD.kind AND NEW.ref_id = OLD.ref_id
     AND NEW.tenant = OLD.tenant AND NEW.hash = OLD.hash AND NEW.prev_hash = OLD.prev_hash AND NEW.created_at = OLD.created_at
     AND jsonb_typeof(NEW.body::jsonb) = 'object' AND (NEW.body::jsonb ? '_enc')
     AND NOT (jsonb_typeof(OLD.body::jsonb) = 'object' AND (OLD.body::jsonb ? '_enc'))
     AND EXISTS (SELECT 1 FROM ledger_rewraps r WHERE OLD.seq BETWEEN r.from_seq AND r.through_seq
                 AND r.expires_epoch > extract(epoch FROM now())) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'append-only table: %', TG_TABLE_NAME;
END $$ LANGUAGE plpgsql"""

_SQLITE_UPDATE = ("CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence WHEN NOT ("
                  "NEW.seq = OLD.seq AND NEW.id = OLD.id AND NEW.chain = OLD.chain AND NEW.kind = OLD.kind AND NEW.ref_id = OLD.ref_id "
                  "AND NEW.tenant = OLD.tenant AND NEW.hash = OLD.hash AND NEW.prev_hash = OLD.prev_hash AND NEW.created_at = OLD.created_at "
                  "AND json_type(NEW.body) = 'object' AND json_extract(NEW.body, '$._enc') IS NOT NULL "
                  "AND NOT (json_type(OLD.body) = 'object' AND json_extract(OLD.body, '$._enc') IS NOT NULL) "
                  "AND EXISTS (SELECT 1 FROM ledger_rewraps r WHERE OLD.seq BETWEEN r.from_seq AND r.through_seq "
                  "AND r.expires_epoch > CAST(strftime('%s', 'now') AS INTEGER))) "
                  "BEGIN SELECT RAISE(ABORT, 'append-only table: evidence'); END")


def upgrade() -> None:
    op.create_table(
        "ledger_rewraps",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("from_seq", sa.Integer(), nullable=False),
        sa.Column("through_seq", sa.Integer(), nullable=False),
        sa.Column("expires_epoch", sa.Integer(), nullable=False),
        sa.Column("records", sa.Integer(), nullable=False),
        sa.Column("certificate", sa.JSON(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("GRANT SELECT, INSERT ON ledger_rewraps TO aegis_app")
        op.execute(_PG_GUARD)
        op.execute("CREATE TRIGGER ledger_rewraps_no_mutate BEFORE UPDATE OR DELETE ON ledger_rewraps FOR EACH ROW EXECUTE FUNCTION aegis_append_only()")
        op.execute("CREATE TRIGGER ledger_rewraps_no_truncate BEFORE TRUNCATE ON ledger_rewraps FOR EACH STATEMENT EXECUTE FUNCTION aegis_append_only()")
    else:
        op.execute("DROP TRIGGER IF EXISTS evidence_no_update")
        op.execute(_SQLITE_UPDATE)
        for ev in ("UPDATE", "DELETE"):
            op.execute(f"CREATE TRIGGER ledger_rewraps_no_{ev.lower()} BEFORE {ev} ON ledger_rewraps "
                       "BEGIN SELECT RAISE(ABORT, 'append-only table: ledger_rewraps'); END")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS ledger_rewraps_no_mutate ON ledger_rewraps")
        op.execute("DROP TRIGGER IF EXISTS ledger_rewraps_no_truncate ON ledger_rewraps")
        op.execute("""CREATE OR REPLACE FUNCTION aegis_evidence_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' AND EXISTS (SELECT 1 FROM ledger_purges p WHERE p.chain = OLD.chain AND OLD.seq <= p.through_seq) THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'append-only table: %', TG_TABLE_NAME;
END $$ LANGUAGE plpgsql""")
    else:
        for ev in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS ledger_rewraps_no_{ev}")
        op.execute("DROP TRIGGER IF EXISTS evidence_no_update")
        op.execute("CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence BEGIN SELECT RAISE(ABORT, 'append-only table: evidence'); END")
    op.drop_table("ledger_rewraps")
