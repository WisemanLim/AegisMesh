"""disaster recovery status (Epic 47, NFR-A5) — 복제·WAL 보관 상태 조회 함수(PostgreSQL 전용).

pg_stat_replication 의 LSN·지연 열은 슈퍼유저·pg_read_all_stats 만 본다. 앱 역할(aegis_app)에 통계 전체 열람을 주는 대신
필요한 값만 JSON 으로 돌려주는 SECURITY DEFINER 함수 하나를 만들고 aegis_app 에만 실행 권한을 준다.

Revision ID: 0019
Revises: 0018
"""
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

FN = """
CREATE OR REPLACE FUNCTION aegis_dr_status() RETURNS json
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
SELECT json_build_object(
  'inRecovery', pg_is_in_recovery(),
  'syncNames', current_setting('synchronous_standby_names'),
  'archiveMode', current_setting('archive_mode'),
  'archiveTimeoutSec', extract(epoch FROM current_setting('archive_timeout')::interval),
  'standbys', COALESCE((SELECT json_agg(json_build_object(
      'name', application_name, 'state', state, 'syncState', sync_state,
      'lagBytes', pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn),
      'replayLagSec', extract(epoch FROM replay_lag)) ORDER BY application_name) FROM pg_stat_replication), '[]'::json),
  'archiver', (SELECT json_build_object('archived', archived_count, 'failed', failed_count, 'lastWal', last_archived_wal,
      'lastAt', last_archived_time, 'lastFailedAt', last_failed_time) FROM pg_stat_archiver))
$$;
REVOKE ALL ON FUNCTION aegis_dr_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegis_dr_status() TO aegis_app;
"""


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(FN)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS aegis_dr_status()")
