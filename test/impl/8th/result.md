# 시험 결과 / Test Result — impl 8th (Epic 8 상시 점검 실행)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite, api + worker + web) · 커밋: —

## 요약 / Summary
- 전체 10 (pytest 145건 포함), 통과 10, 실패 0 → 최종 **PASS** (재시도 1회 — 시험 기대값)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-07 | PASS | `make test` 145 passed |
| F-01 | PASS | `aegismesh-local-worker-1 … python -m app.worker`, restarts=0 (api healthy 대기 후 기동) |
| F-02 | PASS | 등록 직후 `before worker: allow` → `worker ran … block` → `after worker: block qtn_4973dc2ff7dc`, 격리 `('mcp_server','shady-mcp')` |
| F-03 | PASS | 03:45:39 · 03:46:09 두 번 점검(주기 30초), 같은 격리 ID |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 시험이 hits 에 D7-01 규칙 3개를 기대 | 관문 판정은 에이전트당 최상위 규칙 1개, 나머지는 evidence | 시험을 evidence 개수 검사로 | PASS |

## 메모
- 격리 매칭: 도구명(`mcp__server__tool` 분해), `args.server|mcp_server|plugin|skill|agent|model|package`, `params.peer.name`, 에이전트 주체 ID.
- 격리는 모든 관문에 적용된다(에이전트 주체 격리 포함). 해제는 주체 필수 + 원장 기록.
- local 은 SQLite 를 api·worker 두 컨테이너가 같은 볼륨으로 공유(잠금 대기 5초). prod 는 PostgreSQL.

## 첨부 / Logs
- logs/make-test.txt, local-all.txt, ps.txt, f-worker-flow.txt, worker-log.txt
