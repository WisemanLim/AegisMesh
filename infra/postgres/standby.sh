#!/bin/sh
# 대기 서버 진입점 (NFR-A5 · 원장 RPO 0) — 처음이면 주 서버에서 기본 백업을 떠 스트리밍 복제로 시작한다.
# 스트리밍이 붙으면 주 서버에 동기 대기 서버로 등록한다(ALTER SYSTEM synchronous_standby_names).
# 주 서버 기본값은 synchronous_commit=local 이고 원장을 쓴 트랜잭션만 on 으로 커밋을 기다린다(app/db.py).
# 대기 서버가 오래 죽어 있으면 `make db-sync ENV=prod MODE=off` 로 대기를 푼다(RPO 0 해제). 비밀번호는 환경 변수 — 출력하지 않는다.
# 주 서버 연결(psql·pg_basebackup·walreceiver)은 PGSSL* 환경 변수로 상호 TLS(/tls/client = replicator 인증서, NFR-D3).
set -eu
: "${PGDATA:=/var/lib/postgresql/data}"
PRIMARY=${DB_PRIMARY_HOST:-db}
NAME=${DB_STANDBY_NAME:-standby1}
primary_sql() { PGPASSWORD="$DB_PASSWORD" psql -h "$PRIMARY" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -Atq "$@"; }

until pg_isready -h "$PRIMARY" -q; do sleep 1; done
# 복제 역할 — 없으면 만들고, 비밀번호는 매번 환경 변수 값으로 맞춘다(\getenv: 명령줄·로그에 값이 남지 않는다)
primary_sql <<'SQL'
DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'replicator') THEN CREATE ROLE replicator WITH REPLICATION LOGIN; END IF; END$$;
\getenv pw DB_REPLICATION_PASSWORD
ALTER ROLE replicator PASSWORD :'pw';
SQL

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  mkdir -p "$PGDATA" && chown postgres:postgres "$PGDATA" && chmod 700 "$PGDATA"
  t0=$(date +%s)
  PGPASSWORD="$DB_REPLICATION_PASSWORD" gosu postgres pg_basebackup -h "$PRIMARY" -U replicator -D "$PGDATA" -X stream -R -c fast
  echo "standby: 주 서버 복제본 생성 $(( $(date +%s) - t0 ))s"
fi

# 스트리밍이 붙으면 동기 등록 — 이중 fork 로 postgres 의 자식이 되지 않게 한다(고아는 init: true 의 tini 가 거둔다)
( (
  i=0
  while [ $i -lt 300 ]; do
    if [ "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT status FROM pg_stat_wal_receiver" 2>/dev/null)" = streaming ]; then
      primary_sql -c "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 ($NAME)'" && primary_sql -c "SELECT pg_reload_conf()" >/dev/null \
        && echo "standby: $NAME 동기 대기 서버로 등록 (원장 RPO 0)"
      exit 0
    fi
    i=$((i + 1)); sleep 1
  done
  echo "standby: 300초 안에 스트리밍이 붙지 않아 동기 등록 안 함"
) & )

exec docker-entrypoint.sh postgres -c max_connections="${DB_MAX_CONNECTIONS:-300}" -c hba_file=/aegis-pg/pg_hba.conf -c ssl=on -c ssl_cert_file=/tls/server/tls.crt -c ssl_key_file=/tls/server/tls.key -c ssl_ca_file=/tls/server/ca.crt -c cluster_name="$NAME" -c hot_standby=on \
  -c "synchronous_standby_names=" -c "restore_command=cp /backup/wal/%f %p"
