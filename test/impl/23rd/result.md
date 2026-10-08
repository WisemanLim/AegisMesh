# 시험 결과 / Test Result — impl 23rd (Epic 23 인라인 성능·증적 비동기·스트리밍)
- 일자: 2026-10-06 · 대상: prod compose(PostgreSQL 17, runtime 이미지) · Docker Desktop VM 18 CPU — 부하 클라이언트·API·DB 동거 · 커밋: —

## 요약 / Summary
- 전체 11, 통과 11, 실패 0 → 최종 **PASS** (NFR-P1 2,000 rps 는 이 VM 에서 **1,776 rps(작업 16)** — 아래 “목표 대비”)
- `make test` **311 passed** (+ test_perf 5) · `make test-web` 7 + tsc · 경로 7/7 오류 0

## 측정 결과 (동시 64 = 포화, 동시 4 = 경부하 · 단위 ms · 오류 0)
| 단계 | 작업 | 동시 | rps | p50 | p95 | p99 | 비고 |
|------|------|------|-----|-----|-----|-----|------|
| 기준선 | 2 | 64 | 102.5 | 553 | 1,328 | 1,762 | 관문 실행 p95 ≤ 1.4 — 시간은 전부 에이전트 밖 |
| 기준선 | 2 | 4 | 121.1 | 32.4 | 49.3 | 59.8 | 체인 머리 잠금으로 직렬화 |
| ① 증적 비동기 묶음 | 2 | 64 | 198.9 | 210 | 731 | 2,670 | |
| ② 바인딩 일괄 조회·인증 1회 질의 | 2 | 64 | 246.0 | 149 | 615 | 2,707 | 꼬리 = 사건 행 무한 증가 |
| ③ 사건 행 상한·사건/승인 기록 비동기 | 2 | 64 | 269.1 | 198 | 495 | 654 | |
| ④ 바인딩 캐시 2초·응답 직렬화·풀 | 2 | 64 | 365.3 | 154 | 321 | 439 | |
| **최종** (stream 10% 포함) | 2 | 64 | **373.8** | 143 | **342** | 469 | 기준선 대비 3.6배, p95 1/3.9 |
| 최종 | 2 | 4 | **413.2** | **8.2** | **20.0** | 41.6 | |
| 최종 | 8 | 128 | 1,057.9 | 82 | 375 | 497 | |
| 최종 | 16 | 256 | **1,776.4** | 109 | 391 | 574 | 작업 2 대비 4.75배 |

관문 실행(서버 측, 에이전트 합산) p95 — 최종 작업 16·동시 256 포화에서도 예산 안: input 20.9/80 · tool 16.9/20 · output 22.5/150 · stream 22.5/150 (경부하 1.3~1.7).

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T23-01 | PASS | 위 표 기준선 (logs/load-baseline-*.txt) |
| T23-02 | PASS | 요청당 SQL 68 · 원장 적재 9(Finding 8 + 관문 1) — 적재마다 체인 머리 잠금을 커밋까지 보유 → 같은 테넌트 판정 전부 직렬화. 이후: SELECT agents 14, jsonable_encoder 요청당 ~940 호출 (logs/profile-*.txt) |
| T23-03 | PASS | ①~④ 단계별 측정, 오류 0 |
| T23-04 | PASS | 2→8→16 작업: 374 → 1,058 → 1,776 rps (0 오류). 작업 8 에서 DB 연결 초과(too many clients) 발견 → 풀 크기·max_connections 설정 |
| T23-05 | PASS | evidence=queued · 조회 전 flush 로 바로 보임 · 원장 검증 통과 (test_perf) |
| T23-06 | PASS | 단위: 80% → allow 1/5 표본, block 유지, 강등·복귀 원장·알림 “증적 강등”. 실스택(대기열 60·작업 16·동시 256): 1,626 rps 오류 0, 강등/복귀 75쌍, 표본 제외 27,311 · 버림 5,612 모두 원장 기록 |
| T23-07 | PASS | “…임시 키는 AKIAIOSF” + “ODNN7EXAMPLE…” → 첫 청크는 끝 128자 보류, 합친 출력에 키 없음 · 이미지 유출 → block·stop·emit 빈값 · 청크 판정 ≤150ms · 판정 기록에 stream id |
| T23-08 | PASS | minimal-visibility → chatbot-baseline 교체 직후 판정이 새 프로파일 (커밋 시 무효화) |
| T23-09 | PASS | KEEP=3 · 5회 차단 → traceIds 3 · traceCount 5 · findingCount ≥5 |
| T23-10 | PASS | 부하 직후 첫 검증 실패 → 원인: 적재기가 아직 쓰는 중 기록·머리를 다른 시점에 읽음 → 머리 seq 까지 검증으로 수정. 최종 5 체인 1,126,486 건·체크포인트 11,267 통과 |
| T23-11 | PASS | 311 passed · vitest 7 · tsc · /observability·/incidents 등 7 경로 오류 0, 증적 적재 패널 표시 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 처리량 103 rps · p95 1.3초 | 판정마다 원장 9건 동기 적재 + 체인 머리 잠금을 커밋까지 보유 | 증적 비동기 묶음 적재기(체인당 잠금 1회 append_many) | 199 rps |
| 2 | p99 2.7~4.5초(입력 차단) | 같은 주체 반복 차단 시 사건 행 trace·finding ID JSON 이 끝없이 커지며 매번 재기록 | 최근 200건만 보관 + 총계 열(0011) · 사건·승인 원장 기록도 적재기로 | p99 654 |
| 3 | 작업 8 에서 500 (too many clients) | 프로세스당 기본 풀 15 × 8 > PostgreSQL 100 | DB_POOL_SIZE·DB_MAX_OVERFLOW 설정 + DB max_connections 300 | 0 오류 |
| 4 | 부하 직후 원장 검증 ok=false | 검증이 기록 목록과 체인 머리를 다른 시점에 읽음(적재 진행 중) | 머리 먼저 읽고 그 seq 까지만 검증, 검증 중 추가분은 appendedDuringVerify 로 보고 | 통과 |
| — | 부하 공격 표본이 allow | D1 은 untrusted segments, D4-03 은 action 을 본다 | 에이전트 공격 코퍼스와 같은 모양으로 | block·require_approval 발생 |

## 목표 대비 (NFR-P1)
- 이 VM(18 CPU 공유)에서 작업 16 = 1,776 rps. API 가 CPU ~10코어, PostgreSQL ~1.2코어, 부하 클라이언트가 나머지를 쓴다. 작업 2→16 에서 4.75배(코어 대비 선형에 가까움) — 전용 노드(클라이언트·DB 분리)에서 2,000 rps 는 작업 수 조정으로 도달 가능한 범위로 판단하지만 **이번 측정으로 확인한 값은 1,776 rps** 다.
- 남은 비용(요청당 CPU ~5ms): FastAPI 의존성 해석·pydantic 검증·SQLAlchemy ORM(인증 1·테넌트 1·커밋). 다음 단계 후보: 인증 세션 짧은 캐시(회수 지연 허용치 결정 필요), Finding 원장 기록을 관문 기록에 합치기(레코드 수 1/9).

## 설계 결정 기록
- 증적: 인라인 판정(judge·judge:batch·judge:stream)은 대기열에 넣고 응답(evidence=queued|sampled_out|dropped). 작업 프로세스마다 적재 스레드 1개가 묶음(최대 500)을 체인별 잠금 1회로 적재. 대기열 80% 이상 → allow 판정 1/N 표본(위험 판정은 항상), 가득 차면 버림 — 강등·복귀·건수는 원장(kind=evidence)·알림·/v1/observability. 비정상 종료 시 대기분 손실은 의도된 상충(정상 종료는 flush). 판정 외 API 는 처리 전 flush(같은 프로세스 읽기 일관성). EVIDENCE_ASYNC=false 면 이전 동기 적재.
- 바인딩 캐시: 프로파일 적용·에이전트 행·정책 사양·재정의만, TTL 2초, 같은 프로세스의 관련 커밋은 즉시 무효화. 다른 노드는 ≤2초(NFR-O4 10초 안).
- 스트리밍: 서버 무상태 — (보류분+청크) 창 판정, 끝 128자 보류(held 로 반환), final 에서 모두 내보냄. 스트림 청크는 관문 기록 1건 + 위험 판정만 Finding.
- 작업 프로세스 수 WEB_CONCURRENCY(기본 2, 헬름은 api.workers) · 풀 = 작업 × (DB_POOL_SIZE+DB_MAX_OVERFLOW) ≤ DB max_connections.

## 로그
- logs/load-*.txt(단계별 JSON 포함) · profile-baseline.txt · profile-r1.txt · profile-tottime.txt · load-saturation.txt · saturation-ledger.txt · ledger-verify-*.txt · make-test*.txt · stream-smoke.txt · route-sweep.txt
