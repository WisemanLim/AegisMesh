#!/bin/sh
# 복구 훈련 서버 진입점 (NFR-A5 RTO) — 운영 볼륨은 건드리지 않는다. 전용 볼륨(dbdrill)에 기본 백업을 풀고
# 보관 WAL(/backup/wal, 읽기 전용)을 끝까지 재생한 뒤 새 타임라인으로 승격한다. DRILL_BACKUP=<백업 이름> 이 없으면 최신.
set -eu
: "${PGDATA:=/var/lib/postgresql/data}"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  b=${DRILL_BACKUP:-$(ls -1 /backup/base | grep -v '\.partial$' | sort | tail -n 1)}
  [ -n "$b" ] && [ -f "/backup/base/$b/base.tar.gz" ] || { echo "drill: 기본 백업 없음 — make db-backup ENV=prod"; exit 1; }
  t0=$(date +%s)
  mkdir -p "$PGDATA" && chown postgres:postgres "$PGDATA" && chmod 700 "$PGDATA"
  gosu postgres tar -xzf "/backup/base/$b/base.tar.gz" -C "$PGDATA"
  gosu postgres tar -xzf "/backup/base/$b/pg_wal.tar.gz" -C "$PGDATA/pg_wal"
  gosu postgres touch "$PGDATA/recovery.signal"
  echo "drill: 기본 백업 $b 풀기 $(( $(date +%s) - t0 ))s → WAL 재생"
fi
exec docker-entrypoint.sh postgres -c max_connections="${DB_MAX_CONNECTIONS:-300}" -c hba_file=/aegis-pg/pg_hba.conf -c ssl=on -c ssl_cert_file=/tls/server/tls.crt -c ssl_key_file=/tls/server/tls.key -c ssl_ca_file=/tls/server/ca.crt -c archive_mode=off -c "synchronous_standby_names=" \
  -c "restore_command=cp /backup/wal/%f %p"
