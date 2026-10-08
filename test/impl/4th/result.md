# 시험 결과 / Test Result — impl 4th (Epic 4 증적 원장·승인)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite) + prod 리허설 (PostgreSQL 17, uvicorn workers 2) · 커밋: —

## 요약 / Summary
- 전체 12 (pytest 63건 포함), 통과 12, 실패 0 → 최종 **PASS** (재시도 2회)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-08 | PASS | `make test` 63 passed |
| F-01 | PASS | 200 요청 {block 33, transform 100, allow 67} → `verify True records 502 checkpoints 5 체인 검증 통과` |
| F-02 | PASS | `bundle records 502 checkpoint 502`, 묶음에 원문 키 없음 (`raw key in bundle: False`) |
| F-03 | PASS | 원본 `OK 레코드 502건 … 체인·서명 검증 통과` exit 0 / 변조본 `FAIL seq 11: 해시 불일치 (내용 변조)` exit 1 |
| F-04 | PASS | `600 app /app/data/ledger_ed25519.key` |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 동시 적재 시 체인 분기 (SQLite) | SQLite 는 `SELECT … FOR UPDATE` 를 무시 → 두 요청이 같은 prev_hash 를 읽음. local 모드 uvicorn 스레드풀에서 실제 발생 가능 | 머리 행에 무변경 `UPDATE` 를 먼저 보내 쓰기 잠금 선점(SQLite RESERVED, PG 행 잠금) | round 2 |
| 1 | 체크포인트 0건 | 시험 설정: conftest `setdefault` 가 컨테이너 env(100)에 가려짐 | conftest 에서 강제 지정 | round 2 |
| 2 | 같은 세션 연속 적재 시 체인 단절 | 세션 `autoflush=False` + `populate_existing` 이 flush 전 머리 값을 DB 이전 값으로 덮음 | 적재 직후 `flush()` | round 3 PASS |
| F-03 1회차 | 변조본이 OK | 시험 오류: 바꾼 값이 원래 값과 같았음(allow→allow) | 값을 실제로 바꿔 재시험 | FAIL 정상 검출 |

## 메모
- 서명키: `LEDGER_SIGNING_KEY` 미주입(CHANGE_ME) 시 데이터 볼륨에 생성 — 리허설 전용. 운영은 KMS/Secret Manager 주입(NFR-D2).
- 운영 원장 DB 계정에서 직접 INSERT 권한 분리, 보존기한 만료 배치는 후속.

## 첨부 / Logs
- logs/make-test.txt, prod-*.txt, f1-pg-concurrency.txt, f2-export.txt, f3-verify-bundle.txt, f4-keyfile.txt
