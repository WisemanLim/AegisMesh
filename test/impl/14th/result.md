# 시험 결과 / Test Result — impl 14th (Epic 14 관문·정책 관리)
- 일자: 2026-10-06 · 대상: local (SQLite, 0006→0007 이관) + prod 리허설 (PostgreSQL 17, 0006→0007) · 커밋: —
- 브라우저: 헤드리스 Chromium (gstack browse) — 실제 로그인 주체(eng.kim·appr.one·appr.two)

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 1회: 편집기 입력 초기화)
- `make test` **259 passed** (+ test_policy_ops 6) · `make test-web` 7 + tsc · coverage 80/80 · ruff(F,E9) clean

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T14-01 | PASS | `/policies` pol/garam v2·v1, diff `-  minConfidence: 0.5` `+  minConfidence: 0.7` |
| T14-02 | PASS | 틀린 기대 → 단위 시험 1/2, 배포 “배포 차단: 정책 단위 시험 실패”, 버전 v3 그대로 → 고친 뒤 `garam/default@v4 · 시험 2/2` |
| T14-03 | PASS | 단위 시험만 실행 시 버전 불변 + 배포본 대비 diff 표시 (pytest `test_unit_tests_block_deploy`) |
| T14-04 | PASS | 시뮬레이터: 배포 v4 `require_approval` vs 초안 `alert`, 변경 영향 1건(D3-01.high-risk-tool), 시험 케이스 YAML 생성. (판정, 원장, 승인) 수 (38720, 42328, 6) → 동일 |
| T14-05 | PASS | 같은 요청 실제 `judge:batch` → `require_approval` (default@v4) = 시뮬레이터 배포 판정 |
| T14-06 | PASS | 롤백 요청 → 승인 전 v4 유지 → appr.one `pending 1/2` → appr.two `approved 2/2` → v5 (`approval:apr_…`), v5 본문 = v3, 원장 requested·decided×2·action_applied. 요청자 본인 403 은 pytest |
| T14-07 | PASS | `/gates` 입력 80/320ms·도구 20/80ms·출력 150/600ms·offline 경로 밖, 바인딩 에이전트 failMode·p95/몫·호출 수, 강등 기록·alert_only·복귀 조건 |
| T14-08 | PASS | 편집기 검증: 통과 `garam.payments-guard` 23종·관문 예산·승인 필요 항목 / 실패 `spec.extends: 프로파일 no-such 없음` → 저장 → 즉시 사용 적용 23종. nuri 범위 비공개·적용 404 |
| T14-09 | PASS | 259 passed · vitest 7 · tsc · coverage 80/80 · prod PG 0007 + 배포 차단 422·배포·시뮬레이션·관문·사용자 정의 프로파일·격리 시험 7/7 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 편집기 “단위 시험 0/0” — 입력한 YAML 대신 초기값으로 시험 | React 19 는 폼 액션 완료 후 비제어 입력을 초기화 | 편집기 textarea 를 제어 상태로, 시뮬레이터는 onSubmit + startTransition 직접 제출 | round 2 PASS (입력 유지 확인) |
| 1 | 롤백 대상이 v1 이 아닌 v3 로 요청됨 | 시험 선택자 `select[name=to]` 가 diff 폼과 겹침 → 선택 실패, 기본 옵션(v3) | 롤백 필드명을 `target` 으로 분리 | v5 = v3 본문으로 메커니즘 검증 |
| — | 시험이 공용 관리자 역할을 덮어씀(테스트 코드) | `as_user("test.admin", "approver")` 가 역할 교체 | 롤백 요청자를 별도 사용자로 | 259 passed |

## 설계 결정 기록
- 시뮬레이터·단위 시험·`judge:batch` 는 같은 모듈(`app/gating.py`)로 바인딩·실행·합성한다 → 시뮬레이션 결과 = 실제 판정. 시뮬레이터는 저장하지 않는다.
- 정책 롤백은 승인 연계 행동(`approvals.action`): 2인 승인 완료 시에만 해당 버전 본문으로 새 버전을 만든다(이력 보존).
- 사용자 정의 프로파일은 테넌트 소유(`<tenant>.<id>`), 내장 5종은 공유. 화면설계의 폼↔YAML 양방향 동기 중 폼은 검증 보고서(선택 결과·관문 예산·격리·승인 항목)로 대신했다.
- 정책 언어는 내장 선언형 YAML(1차 결정) — Rego·OpenFGA 편집은 범위 밖.

## 첨부 / Logs
- logs/ (비커밋): t14-*.txt, 스크린샷 6장, make-test·test-web·coverage·ruff
