#!/bin/sh
# 원장 동기 복제 켜기/끄기 (NFR-A5) — 주 서버 컨테이너 안에서 실행(make db-sync ENV=prod MODE=on|off).
# off: 대기 서버 장기 장애 때 원장 커밋 대기를 즉시 푼다(재시작 없음, 원장 RPO 0 해제). on: 대기 서버 복구 뒤 다시 건다.
set -eu
case "${1:-}" in
  on) v="FIRST 1 (${DB_STANDBY_NAME:-standby1})" ;;
  off) v="" ;;
  *) echo "usage: sync.sh on|off"; exit 2 ;;
esac
psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -Atq -c "ALTER SYSTEM SET synchronous_standby_names = '$v'" -c "SELECT pg_reload_conf()" >/dev/null
echo "synchronous_standby_names = '$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SHOW synchronous_standby_names")'"
