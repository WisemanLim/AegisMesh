# 시험 결과 / Test Result — impl 47th (Epic 47 백업·복구·동기 복제, NFR-A5)
- 일자: 2026-10-07 · 대상: prod 리허설(로컬 Docker, PostgreSQL 17.10, 원장 약 117만 건·DB 4 GB) + local · 커밋: —

## 요약 / Summary
- 전체 13, 통과 13, 실패 0 → 최종 **PASS** (재시도 4회: 대기 서버 max_connections / burst 분리 행 / 일시 정지 뒤 헬스 대기 2회)
- 실측: 복구 훈련 RTO **45 s**(직전 백업) · **59 s**(WAL 약 464 MB 재생 7.1 s ≈ 65 MB/s 포함) / 목표 1800 s · 장애 조치 RTO **38 s** · 원장 RPO **0**(응답받은 마지막 머리가 승격 서버에 존재) · 일반 데이터 RPO 상한 archive_timeout 60 s(보관 경과 5.6~40.7 s)
- 동기 대기 동작: 대기 서버를 멈추면 일반 커밋 12.9~14.3 ms 로 끝나고 원장 커밋은 대기 · `db-sync off` 면 원장 커밋도 즉시
- `make test` 407 passed(logs/make-test.txt) · `make test-web` 15 passed + tsc · `/observability` ko·en 접근성 위반 0
- 측정으로 바꾼 것: 기본 백업 기본 주기 86400 → **14400 s**. 최대 부하(252 rps) WAL 생성 7 MB/s 면 하루치 재생이 약 2.5 시간이라 RTO 30분을 넘는다 → 4시간 주기면 최악 재생 약 26분

## 구현
- `docker-compose.prod.yml`: db 에 WAL 보관(`archive_mode=on` → 볼륨 `dbbackup`, `archive_timeout=${DB_ARCHIVE_TIMEOUT_SEC:-60}`)·`synchronous_commit=local`·`hba_file` · 새 서비스 `db-standby`(init, 첫 기동 pg_basebackup -R, 스트리밍 후 동기 등록) · `db-backup`(주기 기본 백업) · `db-drill`(`drill` 프로파일, 전용 볼륨)
- `infra/postgres/`: `pg_hba.conf`(replicator 원격 SCRAM) · `entry.sh` · `standby.sh` · `backup.sh`(once·loop·list, 보관 WAL 정리) · `drill.sh` · `sync.sh`
- `app/db.py`: 증적을 쓴 트랜잭션만 `SET LOCAL synchronous_commit TO on`(PostgreSQL, after_flush) · `migrations/0019_dr_status.py`: SECURITY DEFINER `aegis_dr_status()`(aegis_app 실행 권한만)
- `app/dr.py`: status·heads·burst·probe·check(--host)·record · `GET /v1/observability/dr` · 콘솔 `/observability` 재해 복구 카드(ko·en)
- `scripts/dr_drill.sh` restore·failover · Makefile `db-backup`·`db-restore-drill`·`db-failover-drill`(CONFIRM=1)·`db-sync` (모두 ENV=prod 전용)
- env `DB_REPLICATION_PASSWORD`(prod CHANGE_ME)·`DB_ARCHIVE_TIMEOUT_SEC`·`DB_BACKUP_INTERVAL_SEC`·`DB_BACKUP_KEEP` — `.env.local`·`.env.prod`·`.env.example`
- `test/test_dr.py` 3건

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 407 passed · `test_dr` 3 |
| C02 | PASS | `make prod-build`(round 1 실패 → 수정) → `db-migrate ENV=prod` 0019 · `db-ping` postgres OK · 대기 서버 복제본 생성 3~4 s, "standby1 동기 대기 서버로 등록" |
| C03 | PASS | role primary · standby1 streaming/sync lag 0 B · ledgerRpo0 true · 보관 failed 0 · timeoutSec 60 (logs/dr-status-1.json) |
| C04 | PASS | 일반 트랜잭션 `local` · 원장 트랜잭션 `on` · 커밋 뒤 `local` (logs/c04-sync-commit.txt) · 부하 비교 동기 on 217 rps / off 166 rps — 호스트 잡음 범위, 판정 경로는 비동기 적재라 영향 없음 |
| C05 | PASS | 361 MB(base.tar.gz + pg_wal.tar.gz + backup_manifest + START_WAL) 23 s · 목록 2개 · 보관 WAL 7개 |
| C06 | PASS | 기준점 체인 4 → 복원·재생 13 s · 원장 1,126,659건 검증 31 s · 기준점 누락 0 · RTO 45 s · 원장 seq 1132074 기록 · 훈련 볼륨 삭제. 오래된 백업(DRILL_BACKUP) 재훈련: WAL 재생 7.1 s · 1,174,200건 · RTO 59 s |
| C07 | PASS | 보관 경과 7.6 s·5.6 s(훈련 시작 시점) · 40.7 s(상태 조회) ≤ 300 s · archive_timeout 60 s |
| C08 | PASS | 대기 서버 일시 정지 중 probe: plainCommitMs 14.0 · ledgerCommitWaiting true |
| C09 | PASS | 원장 20건 응답(seq 1179699) 직후 주 서버 일시 정지 → pg_promote → 승격 서버 원장 1,174,286건 검증 OK·missingHeads [] · RTO 38 s → 주 서버 재개·동기 해제·대기 서버 재복제·재등록 ledgerRpo0 true · 원장 seq 1179700 기록 |
| C10 | PASS | `db-sync MODE=off` → 대기 서버 정지 중에도 ledgerCommitWaiting false → `MODE=on` → syncStandbys [standby1] |
| C11 | PASS | ENV 없는 `make db-backup` 거부 · CONFIRM 없는 `make db-failover-drill ENV=prod` 거부 (logs/c11-guards.txt) |
| C12 | PASS | local `/observability` ko·en axe 위반 0, en 한글은 기존 마스킹 예시 입력(textarea)뿐 · 적용 분기(prod) 는 API 응답 + tsc 로 확인 — prod 콘솔은 특권 TOTP 계정이 필요해 화면 확인 생략 |
| C13 | PASS | 훈련 뒤 주 서버 원장 1,245,622건 검증 통과 37 s · kind=dr 89건(burst·probe·훈련 기록) · lastDrill = failover-drill ok rtoSec 38 |

## 회차 / Rounds
- round 1: 대기 서버 기동 실패 "max_connections = 100 is a lower setting than on the primary server, where its value was 300" → standby·drill 에 `DB_MAX_CONNECTIONS` 전달
- round 1': `make test` 137 — `make local-stop`(--remove-orphans)이 같은 프로젝트의 시험 컨테이너를 지움(동시 실행 실수) → 재실행
- round 2: 장애 조치 훈련 `burst` DetachedInstanceError(세션 밖에서 만료 행 읽기) → 세션 안에서 seq·hash 복사, 단위 시험에 burst 추가 (주 서버 정지 전에 멈춤)
- round 3: 복귀 단계 `up --wait db-standby` "dependency failed: db is unhealthy" — 일시 정지 중 실패한 헬스 검사가 남음 → `up --wait db` 추가
- round 4: `up --wait db` 도 unhealthy 면 기다리지 않고 실패, 그동안 승격된 서버가 동기 대상으로 남아 주 서버 원장 커밋이 약 1분 대기 → 동기 해제를 먼저, 헬스는 폴링. 이 결함을 문서화(대기 서버 승격 뒤에는 반드시 `db-sync off`)
- round 5: 3회차 전 단계 통과. `lastDrill` 이 burst·probe 기록을 집음 → 훈련 결과(ref restore-drill·failover-drill)만

## 남은 것 / Notes
- 실제 운영: 기본 백업·WAL 보관 볼륨을 다른 호스트·객체 저장으로 복사해야 호스트 상실에 견딘다(이 리허설은 같은 호스트 볼륨). K8s 는 운영자(CloudNativePG 등)의 동기 복제로 대체.
- 대기 서버 장애 중에는 원장 커밋이 기다린다(일관성 우선). 판정 경로는 비동기 적재라 응답은 계속되지만 적재 대기열이 찬다 → `make db-sync ENV=prod MODE=off` 로 풀고 복구 뒤 on.
- `test/test_ledger.py::test_tampered_bundle_fails` 는 단독 실행 시 실패(첫 레코드 body 에 이미 verdict=allow — 실행 순서 의존). 전체 실행에서는 통과. 이번 변경과 무관 — 손대지 않음.
