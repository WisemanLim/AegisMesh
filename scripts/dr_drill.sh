#!/usr/bin/env bash
# 재해 복구 훈련 (Epic 47 · NFR-A5) — make db-restore-drill / db-failover-drill ENV=prod 가 호출한다. 비밀 값은 출력하지 않는다.
#   restore  : 기준점(원장 머리) → WAL 전환·보관 대기 → [SOURCE=offsite: 객체 저장의 암호화 복사본을 받아 dboffsite 에 풀기]
#              → 전용 볼륨(dbdrill)에 최신 기본 백업 + 보관 WAL 재생·승격
#              → 원장 전체 검증·기준점 존재 확인 → RTO·RPO 측정을 원장(kind=dr)에 기록 → 훈련 컨테이너·볼륨 삭제(KEEP=1 이면 유지)
#   failover : 동기 대기 확인 → 대기 서버 정지 중 원장 커밋은 대기·일반 커밋은 즉시 → 원장 N 건 커밋 직후 주 서버 일시 정지
#              → 대기 서버 승격 → 원장 검증(마지막으로 응답받은 머리 존재 = RPO 0) → 주 서버 재개·동기 해제
#              → 승격된 대기 서버 볼륨(dbstandby, 주 서버의 파생 복제본)을 지우고 다시 복제 → 동기 재등록 → 기록
set -euo pipefail
: "${DC:?DC (compose 명령) 필요}"
P=$(sed -E 's/.* -p ([^ ]+) .*/\1/' <<<"$DC")
now() { date +%s; }
pg() { $DC exec -T "$1" sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -Atqc \"$2\""; }
js() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

restore() {
  echo "== 기준점"
  local heads seg age t1 t2 t3 chk ok body
  heads=$($DC exec -T api python -m app.dr heads)
  age=$($DC exec -T api python -m app.dr status | js 'd["archive"]["ageSec"]')
  seg=$(pg db "SELECT pg_walfile_name(pg_switch_wal())")
  until [ "$(pg db "SELECT coalesce(last_archived_wal, '') >= '$seg' FROM pg_stat_archiver")" = t ]; do sleep 1; done
  echo "원장 체인 $(js 'len(d)' <<<"$heads")개 머리 기록 · 직전 WAL 보관 경과 ${age}s (archive_timeout 상한) · 현재 세그먼트 $seg 보관 완료"
  local fetched=null
  $DC --profile drill rm -sf db-drill >/dev/null 2>&1 || true
  docker volume rm "${P}_dbdrill" >/dev/null 2>&1 || true
  t1=$(now)
  if [ "${SOURCE:-local}" = offsite ]; then              # 호스트 상실 가정 — 객체 저장의 암호화 복사본만으로
    echo "== 외부 복사 → 받아 풀기 (전용 볼륨 ${P}_dboffsite)"
    $DC exec -T backup-ship python -m app.offsite ship >/dev/null
    docker volume rm "${P}_dboffsite" >/dev/null 2>&1 || true
    fetched=$($DC run --rm --no-deps -T -v "${P}_dboffsite:/restore" backup-ship python -m app.offsite fetch /restore | tail -1)
    echo "$fetched"
    export DRILL_SOURCE_VOLUME=dboffsite
  fi
  echo "== 복원 (전용 볼륨 ${P}_dbdrill — 운영 볼륨 무변경)"
  $DC --profile drill up -d --wait db-drill
  t2=$(now)
  $DC --profile drill logs --no-log-prefix db-drill 2>&1 | grep -E "drill:|redo done|archive recovery complete|selected new timeline|ready to accept" | sed 's/^/  /' || true
  echo "== 검증 (복원 DB 에서 원장 전체 재계산 + 기준점 머리 확인)"
  chk=$($DC --profile drill run --rm --no-deps -T api python -m app.dr check --host db-drill "$heads" || true)
  t3=$(now)
  echo "$chk" | js 'json.dumps(d, ensure_ascii=False)'
  ok=$(echo "$chk" | js 'str(d["ok"]).lower()')
  body=$(printf '{"drill":"restore-drill","source":"%s","ok":%s,"rtoSec":%d,"restoreSec":%d,"verifySec":%d,"archiveAgeSec":%s,"targetRtoSec":1800,"fetch":%s,"check":%s}' \
    "${SOURCE:-local}" "$ok" $((t3 - t1)) $((t2 - t1)) $((t3 - t2)) "$age" "$fetched" "$chk")
  echo "RTO(${SOURCE:-local}: 받기+복원+재생+검증) $((t3 - t1))s / 목표 1800s · 복원·재생 $((t2 - t1))s · 검증 $((t3 - t2))s · 결과 ok=$ok"
  $DC exec -T api python -m app.dr record "$body" | js '"원장 기록 seq " + str(d["seq"])'
  if [ "${KEEP:-}" != 1 ]; then
    $DC --profile drill rm -sf db-drill >/dev/null 2>&1
    docker volume rm "${P}_dbdrill" >/dev/null
    docker volume rm "${P}_dboffsite" >/dev/null 2>&1 || true
    echo "훈련 컨테이너·볼륨 삭제"
  fi
  [ "$ok" = true ]
}

failover() {
  echo "== 사전 상태"
  $DC exec -T api python -m app.dr status | js '{k: d[k] for k in ("role", "syncStandbys", "ledgerRpo0")}'
  [ "$($DC exec -T api python -m app.dr status | js 'd["ledgerRpo0"]')" = True ] || { echo "동기 대기 서버 없음 — 훈련 중단"; exit 1; }
  echo "== 대기 서버 정지 → 원장 커밋은 대기, 일반 커밋은 즉시"
  $DC pause db-standby >/dev/null
  $DC exec -T api python -m app.dr probe
  $DC unpause db-standby >/dev/null
  echo "== 원장 20 건 커밋(각각 동기 응답) → 곧바로 주 서버 일시 정지(장애)"
  local ack t1 t2 chk ok n=20
  ack=$($DC exec -T api python -m app.dr burst $n)
  $DC pause db >/dev/null
  t1=$(now)
  echo "응답받은 마지막 머리 $(js 'json.dumps(d)' <<<"$ack")"
  echo "== 대기 서버 승격 → 원장 검증"
  pg db-standby "SELECT pg_promote(true, 60)" >/dev/null
  chk=$($DC run --rm --no-deps -T api python -m app.dr check --host db-standby "$ack" || true)
  t2=$(now)
  echo "$chk" | js 'json.dumps(d, ensure_ascii=False)'
  ok=$(echo "$chk" | js 'str(d["ok"] and not d["inRecovery"]).lower()')
  echo "RTO(승격+검증) $((t2 - t1))s / 목표 1800s · 원장 RPO 0 = 마지막 응답 머리 존재 $(echo "$chk" | js 'not d["missingHeads"]')"
  echo "== 복귀 — 주 서버 재개 · 동기 해제 · 대기 서버 재복제(${P}_dbstandby)"
  $DC unpause db >/dev/null
  $DC exec -T db sh /aegis-pg/sync.sh off            # 승격된 대기 서버는 더 이상 동기 대상이 아니다 — 원장 커밋 대기를 먼저 푼다
  until [ "$(docker inspect -f '{{.State.Health.Status}}' "$($DC ps -q db)")" = healthy ]; do sleep 1; done   # 일시 정지 중 실패한 헬스 검사 회복
  $DC rm -sf db-standby >/dev/null 2>&1
  docker volume rm "${P}_dbstandby" >/dev/null
  $DC up -d --wait db-standby
  for _ in $(seq 1 60); do
    [ "$($DC exec -T api python -m app.dr status | js 'd["ledgerRpo0"]')" = True ] && break
    sleep 2
  done
  $DC exec -T api python -m app.dr status | js '{k: d[k] for k in ("role", "syncStandbys", "ledgerRpo0")}'
  $DC exec -T api python -m app.dr record "$(printf '{"drill":"failover-drill","ok":%s,"rtoSec":%d,"targetRtoSec":1800,"ackHeads":%s,"check":%s}' \
    "$ok" $((t2 - t1)) "$ack" "$chk")" | js '"원장 기록 seq " + str(d["seq"])'
  [ "$ok" = true ]
}

"${1:?restore | failover}"
