"""evidence append-only triggers (DP9, NFR-S) — UPDATE·DELETE(·TRUNCATE) 를 DB 수준에서 거부

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = ("evidence", "ledger_checkpoints")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""CREATE OR REPLACE FUNCTION aegis_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'append-only table: %', TG_TABLE_NAME; END $$ LANGUAGE plpgsql""")
        for t in TABLES:
            op.execute(f"CREATE TRIGGER {t}_no_mutate BEFORE UPDATE OR DELETE ON {t} "
                       f"FOR EACH ROW EXECUTE FUNCTION aegis_append_only()")
            op.execute(f"CREATE TRIGGER {t}_no_truncate BEFORE TRUNCATE ON {t} "
                       f"FOR EACH STATEMENT EXECUTE FUNCTION aegis_append_only()")
    else:  # sqlite (mysql/mariadb 는 SIGNAL 문법 — 해당 엔진 채택 시 추가)
        for t in TABLES:
            for ev in ("UPDATE", "DELETE"):
                op.execute(f"CREATE TRIGGER {t}_no_{ev.lower()} BEFORE {ev} ON {t} "
                           f"BEGIN SELECT RAISE(ABORT, 'append-only table: {t}'); END")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for t in TABLES:
            op.execute(f"DROP TRIGGER IF EXISTS {t}_no_mutate ON {t}")
            op.execute(f"DROP TRIGGER IF EXISTS {t}_no_truncate ON {t}")
        op.execute("DROP FUNCTION IF EXISTS aegis_append_only()")
    else:
        for t in TABLES:
            for ev in ("update", "delete"):
                op.execute(f"DROP TRIGGER IF EXISTS {t}_no_{ev}")
