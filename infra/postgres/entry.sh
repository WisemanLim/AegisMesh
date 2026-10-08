#!/bin/sh
# 주 서버 진입점 (NFR-A5) — WAL 보관 디렉터리(/backup, 볼륨 dbbackup)를 postgres 소유로 만든 뒤 공식 진입점으로 넘긴다.
set -eu
mkdir -p /backup/wal /backup/base
chown postgres:postgres /backup /backup/wal /backup/base
exec docker-entrypoint.sh "$@"
