# 시험 결과 / Test Result — impl 3rd (Epic 3 관문·오케스트레이션·정책·프로파일)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite) · 커밋: —

## 요약 / Summary
- 전체 15 (pytest 52건 포함), 통과 15, 실패 0 → 최종 **PASS** (재시도 1회 — 시험 코드 오류)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-12 | PASS | `make test` 52 passed |
| F-01 | PASS | `apply chatbot-baseline enforce ['d1-05','d1-07','d2-03'] missing 11` |
| F-02 | PASS | `input-attack block ['D1-05.unicode-tag']`, `output-key transform key [REDACTED_ANTHROPIC_KEY]` |
| F-03 | PASS | 입력 관문 p95 0.13ms (예산 80ms), 출력 관문 p95 0.21ms (예산 150ms), n=200 — 관문 내부 계측 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | test_transform_not_persisted 실패 | 시험이 findings[0](d1-07, allow)을 집음 — 결과는 에이전트 ID 순 정렬 | d2-03 판정을 ID 로 선택 | round 2 PASS |

## 메모
- 지연은 현재 바인딩 3종 기준. 1단계 19종이 붙는 Epic 5 에서 재측정한다.
- 미리보기 재생(PRD §11.6 영역 4)은 원문 미보존 기본값(NFR-D1)과 충돌 — 표본 입력을 받아 재생하는 API 로 후속 설계 필요.
- 오탐 예산 자동 강등(NFR-Q6)은 상태값 `alert_only` 반영까지만 구현. 예산 집계·자동 전환은 후속.

## 첨부 / Logs
- logs/make-test.txt, local-all.txt, f1-apply.txt, f2-gates.txt
