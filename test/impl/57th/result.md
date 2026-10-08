# 시험 결과 / Test Result — impl 57th (Epic 57 원장 평문 잔존 제거)
- 일자: 2026-10-08 · 대상: local + prod 리허설(PostgreSQL 0022, 원장 157만 건, 동기 대기 서버) · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 2회: 시험 시드가 컴파일 캐시에 막힘 / worker·CLI 동시 실행 경합 예방)
- 평문 원장 기록 **1,340,973건 → 0** (전체 1,601,483건) — 2인 승인 창 01:54:08 열림 → 01:59:10 끝(약 5분, worker 주기 + `make ledger-rewrap` 이 SKIP LOCKED 로 나눠 처리)
- 원장 전체 검증 OK — 1,601,483건·체크포인트 16,016·불량 0(54 s). 해시·seq·체인 그대로
- 덤프의 본문 평문 표식 chatbot-baseline 239,959 → **0** · svc.loadtest 3,726 → 0 · load.test 37,014 → 1(= `ref_id` 색인 메타데이터, 본문 아님)
- 힙 파일 옛 행 판 표식 108,353 → `VACUUM FULL`(22 s) 뒤 본 파일·TOAST **0**
- 재암호화 중 판정 부하 오류 **0/5,638** (처리량은 같은 VM 을 나눠 써 94 rps·p95 879 ms — 유지 보수 창 권장) · `make test` 458 passed

## 구현
- 마이그레이션 0022 — `ledger_rewraps`(추가 전용 창: seq 구간·만료 유닉스 초·서명 증명서) · 트리거 `aegis_evidence_guard`(PG)·`evidence_no_update`(SQLite): 창 안에서 '평문 → `{"_enc"}` 봉투 암호문, 다른 열 불변' 만 허용, 그 밖의 UPDATE·암호문 다시 쓰기·창 표 수정 거부
- `app/ledger_rewrap.py` — 저장 형식(앞부분)으로 평문 판별 · 요청(2인 승인) · 승인 실행 = 서명 증명서 + 창 · 묶음 재암호화(묶음마다 커밋, PG `FOR UPDATE SKIP LOCKED`) · 끝나면 원장 `ledger_rewrapped` · CLI `status|run`
- `GET /v1/evidence/rewrap` · `POST /v1/evidence/rewrap:request`(privacy·플랫폼 범위) · worker 주기(창이 열려 있으면 최대 60 s씩) · `make ledger-rewrap [ENV=prod] [VACUUM=1]` · `kms.status(full)` 의 `plaintextTotal` · env `LEDGER_REWRAP_WINDOW_SEC` · `test/test_ledger_rewrap.py` 2
- 기존 시험 보정: `test_ledger` 변조 시험이 원래 값과 같은 `verdict: allow` 를 넣으면 변조가 아님(순서 의존) → `tampered`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 458 passed · test_ledger_rewrap 2 |
| C02 | PASS | c02-trigger.txt — 창 없이 body·hash UPDATE·DELETE 모두 `append-only table: evidence`, `ledger_rewraps` 추가 전용 트리거 |
| C03 | PASS | c03-request.txt — 개발자 403 · 요청 200(평문 1,340,973) · 중복 409 · 승인 1명 = 창 0 · 2명 = 창 rwp_4cb1035ec258(만료 6시간, signatureOk, 승인자 2, KEK builtin:v2) |
| C04 | PASS | c04-status-after.txt 평문 0 · c04-worker.txt · c04-ledger-rewrap.txt(CLI 672,973건 218 s) · c04-verify.txt · c04-ledger-events.txt(requested → opened → rewrapped) |
| C05 | PASS | c05-dump-before/after.txt · c05-files-before-vacuum.txt 108,353 · c05-files-after-vacuum.txt 본 파일 3구간·TOAST 0 |
| C06 | PASS | c06-loadtest.txt 오류 0/5,638 · 관문 실행 p95 22/17/26 ms(예산 이내), 종단 p95 879 ms(재암호화와 자원 경합) |

## 회차 / Rounds
- round 1: 시험 시드(평문 적재)를 열 타입 메서드 교체로 만들었더니 앞 시험이 컴파일한 INSERT 의 bind 처리기가 캐시돼 암호화됨 → 일반 JSON 표 객체로 직접 적재(해시·머리 갱신은 원장과 같게)
- round 2: worker 와 `make ledger-rewrap` 이 같은 행을 집으면 두 번째 갱신이 트리거에 막혀 묶음이 실패 → PG 는 `FOR UPDATE SKIP LOCKED` 로 나눠 처리(같은 창에서 동시 실행 오류 0)

## 남은 것 / Notes
- 옛 기본 백업·보관 WAL·외부 복사본에 든 평문은 보존 주기(`DB_BACKUP_KEEP` 12 × 4시간)로 사라진다 — 즉시 없애려면 재암호화 뒤 새 기본 백업을 만들고 옛 것을 정리하는 운영 절차.
- `kind`·`ref_id`·`tenant` 는 색인용 평문 메타데이터(49th 설계) — 본문(판정·근거·사유)만 암호화 대상.
- 재암호화는 판정과 CPU·DB 를 나눠 쓴다 — 유지 보수 창에서 돌리거나 `LEDGER_REWRAP_BATCH` 를 줄인다.
