# 시험 결과 / Test Result — impl 51st (Epic 51 깊은 검사 실효화)
- 일자: 2026-10-07 · 대상: local + prod 리허설(PostgreSQL 0020, 상호 TLS, guard 1개) · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 4회: 시험 설정 1 / guard-up 옛 네트워크 / 로컬 SQLite 부하 잠김 → prod 로 / 처리량 집계 방식)
- **부하 중 선별**(prod, 정상 부하 210 rps, CPU 를 부하와 나눠 씀): 모델은 구간 288 s 동안 35건만 처리 — 선입선출이었다면 검사 비율 약 **0.12%**(35 / 약 2.9만). 선별 대기열(인라인 n-gram 점수 높은 입력 먼저)로 그 처리량의 대부분이 주입 공격에 쓰여 **주입 공격 경보 30/40(75%)**
- **세션 격리**: 경보 30건 → 주체·세션 격리 → 같은 주체의 다음 요청 **30/30 인라인 차단**(PLATFORM.quarantine). 해제는 2인(1명 승인 = 유지), 기한(기본 1시간) 지나면 자동 해제
- 인라인이 이미 경보·차단한 입력은 깊은 검사 대기열에 넣지 않는다(모델 처리량 보존)
- `make test` 433 passed · `make test-web` 16 + tsc

## 구현
- `migrations/0020_quarantine_expiry.py` · `Quarantine.expires_at` · 종류 principal·session
- `app/scanner.py` — `quarantine(..., expires_at)`, `match()` 가 기한 안의 주체·세션 격리도 본다
- `app/gating.py` — 깊은 검사 대기열을 우선순위(인라인 D1-03 n-gram 분류기 점수) 정렬 + 전용 작업자, 가득 차면 가장 낮은 항목을 뺌(evicted)·새 항목이 가장 낮으면 건너뜀(skipped) · 경보 시 주체·세션 격리(`GUARD_QUARANTINE_SEC`, 0 = 경보만) · 인라인 판정이 allow 일 때만
- `POST /v1/quarantine/{id}:release` — principal·session 은 202 + 2인 승인(기존 `quarantine_release`) · 목록에 `expiresAt`·`expired`
- `infra/guard/server.py` `/health` 처리 건수 · `make guard-up` 은 `--build --force-recreate`(멈춘 컨테이너의 옛 네트워크 문제)
- 콘솔 `/scan` 기한 표시·"해제 요청(2인)"·승인 요청 메시지, en 번역 패턴(서버 사유) · `test/test_guard.py` +4 · `apps/web/test/i18n.test.ts` +1
- env `GUARD_QUARANTINE_SEC=3600`(local·prod·example)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 433 passed · test_guard 10 |
| C02 | PASS | prod alembic 0020 |
| C03 | PASS | logs/c03-select-quarantine-prod.txt — 주입 40 인라인 allow 40 · 모델 처리 35(구간+대기 138+150 s) · 경보 30/40 · 격리 주체 30 · 다음 요청 차단 30/40(격리된 30 전부). 부하 210.6 rps 오류 0/31,592 |
| C04 | PASS | 주체 inj.0: 1명 승인 뒤 active True·pending → 2명 뒤 False(approval:…) · 해제 주체 새 세션 allow · 그 세션 inj-s0 은 block 유지 · 다른 주체 inj.1 block |
| C05 | PASS | test_quarantine_expires(기한 1 s → 1.2 s 뒤 allow) |
| C06 | PASS | `make test-web` 16 — 서버 사유·근거 메모 en 패턴 번역 시험 |

## 회차 / Rounds
- round 1: 선별 시험이 대기 상한 1 에서 붙잡기 작업 두 번째를 건너뜀 → 작업자가 다 가져간 뒤 상한을 줄이게
- round 2: `make guard-up` "network … not found" — 로컬 스택을 다시 만든 뒤 멈춰 있던 guard 가 옛 네트워크를 가리킴 → `--force-recreate`(+ `--build`)
- round 3: 로컬 SQLite 가 250 rps 쓰기에서 "database is locked" → 부하 실험은 prod(PG)로
- round 4: prod api 는 작업 프로세스 2개라 `deepCheck` 통계가 프로세스별 → 원장(gate_async)·격리 표·guard 처리 건수로 집계. 관문 기록 수는 증적 표본 강등으로 적게 잡혀 분모는 부하 클라이언트 실측

## 남은 것 / Notes
- 놓친 10건은 대기열에서 밀렸거나(n-gram 점수 낮음) 모델이 낮게 본 것 — 모델 처리량이 늘수록 줄어든다(GPU·복제본).
- 첫 요청은 이미 응답이 나간 뒤다(깊은 검사는 차단 불가). 격리는 다회차 공격을 막는다.
