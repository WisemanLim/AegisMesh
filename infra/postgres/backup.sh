#!/bin/sh
# 기본 백업 (NFR-A5) — pg_basebackup(tar·gzip·WAL 포함) → /backup/base/<UTC 시각>. 최근 DB_BACKUP_KEEP 개만 남기고,
# 남은 가장 오래된 백업보다 앞선 보관 WAL 은 정리한다. 복구 = 기본 백업 + /backup/wal 재생(make db-restore-drill ENV=prod).
#   backup.sh once | loop | list
set -eu
[ "$(id -u)" = 0 ] && exec gosu postgres sh "$0" "$@"
PRIMARY=${DB_PRIMARY_HOST:-db}
KEEP=${DB_BACKUP_KEEP:-12}
B=/backup/base
export PGPASSWORD="$DB_REPLICATION_PASSWORD"

done_list() { ls -1 "$B" | grep -v '\.partial$' | sort; }

once() {
  until pg_isready -h "$PRIMARY" -q; do sleep 1; done
  # 정리 경계: 백업 시작 직전의 현재 WAL 파일 — 실제 시작점보다 같거나 앞이라 필요한 WAL 을 지우지 않는다
  wal=$(psql -h "$PRIMARY" -U replicator -d "${DB_NAME:-app}" -Atqc "SELECT pg_walfile_name(pg_current_wal_lsn())")
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  t0=$(date +%s)
  pg_basebackup -h "$PRIMARY" -U replicator -D "$B/$ts.partial" -Ft -z -X stream -c fast
  echo "$wal" > "$B/$ts.partial/START_WAL"
  mv "$B/$ts.partial" "$B/$ts"
  echo "backup $ts — $(du -sh "$B/$ts" | cut -f1) · $(( $(date +%s) - t0 ))s · WAL 경계 $wal"
  n=$(done_list | wc -l)
  [ "$n" -gt "$KEEP" ] && done_list | head -n $((n - KEEP)) | while read -r old; do rm -rf "${B:?}/$old"; echo "prune $old"; done
  pg_archivecleanup /backup/wal "$(cat "$B/$(done_list | head -n 1)/START_WAL")"
}

list() {
  for d in $(done_list); do echo "$d  $(du -sh "$B/$d" | cut -f1)  WAL 경계 $(cat "$B/$d/START_WAL")"; done
  echo "보관 WAL $(ls -1 /backup/wal | wc -l) 개 · $(du -sh /backup/wal | cut -f1) · 최근 $(ls -1 /backup/wal | sort | tail -n 1)"
}

loop() {
  rm -rf "$B"/*.partial
  every=${DB_BACKUP_INTERVAL_SEC:-14400}
  # 최근 주기 안의 백업이 없으면 바로 1회 (스택을 오래 내려 두었다 올린 경우)
  [ -n "$(find "$B" -mindepth 1 -maxdepth 1 -type d ! -name '*.partial' -mmin -$((every / 60)) 2>/dev/null)" ] || once || echo "backup 실패 — 다음 주기에 재시도"
  while :; do sleep "$every"; once || echo "backup 실패 — 다음 주기에 재시도"; done
}

"${1:-once}"
