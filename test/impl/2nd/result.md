# 시험 결과 / Test Result — impl 2nd (Epic 2 레지스트리·데이터)
- 일자: 2026-10-06 · 대상: aegismesh (local=SQLite / prod=PostgreSQL 17) · 커밋: —

## 요약 / Summary
- 전체 11 (pytest 34건 포함), 통과 11, 실패 0 → 최종 **PASS** (재시도 0회)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-07 | PASS | `make test` 34 passed |
| F-01 | PASS | `coverage 3/80 strict 2/19`, `risk-items 80 {available 3, missing 77}` |
| F-02 | PASS | migrate exit 0, `alembic_version 0002`, `seed: {'riskItems': 80, 'agents': 3}` |
| F-03 | PASS | `{"env":"prod","db":{"engine":"postgres","status":"ok"}}`, d1-05·d1-07·d2-03 active, 422 |
| F-04 | PASS | UPDATE/DELETE/TRUNCATE → `ERROR: append-only table: evidence` |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| — | alembic DeprecationWarning(path_separator) | 스캐폴드 alembic.ini 구형 키 | `path_separator = os` 추가 | 경고 제거 |

## 메모
- F-04 확인을 위해 psql 로 직접 넣은 시험 행(`evd_t`)은 추가 전용이라 지울 수 없어 체인을 깬다 → 로컬 리허설 볼륨(`aegismesh-prod_dbdata`·`appdata`)을 제거해 초기화. 운영 원장에는 직접 INSERT 경로가 없어야 한다(DB 권한 분리 — 후속).
- 보존기한 만료 처리(PRD §12.6 "승인된 배치")는 트리거를 우회해야 하므로 별도 DB 역할·절차가 필요 — 후속.
- MySQL/MariaDB 용 트리거(SIGNAL)는 미구현 — 해당 엔진 채택 시 추가.

## 첨부 / Logs
- logs/make-test.txt, local-all.txt, f-local-*.txt, prod-build.txt, prod-migrate.txt, prod-seed.txt, f-prod-*.txt, prod-volume-reset.txt
