# 시험 결과 / Test Result — impl 27th (Epic 27 에이전트 설정·관문 상세·강등 현황)
- 일자: 2026-10-06 · 대상: local compose (api 8000 · web 3000) + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 14, 통과 14, 실패 0 → 최종 **PASS** (재시도 2회: 관문 상세의 재배치 목록이 바인딩에 의존 · `dict(Result)` 오류 / E2E 부하 생성기가 에이전트 측정 바깥에서 지연을 넣음 → 측정 안쪽 detect 로)
- `make test` **338 passed** (+ test_agent_config 9, test_policy_ops diff 시험을 원복 버전에 견고하게) · `make test-web` 14 + tsc 0 · coverage 80/80 · 엄격 43/43
- 실측(로컬): 느린 에이전트(d4-01 +60ms) 출력 관문 p95 65.7ms(예산 150ms 의 44%) → d4-01 p95 65.1ms > 몫 30ms → 재배치 제안 "관문 p95 65.7 → 0.7ms 예상"; 하드 타임아웃 5ms·d4-01 20ms → 강등 5건(fail-closed 차단), 상단 칩 적색·셸 배너·강등 이력

## 구현
- 매니페스트 `spec.config`(`ConfigParam`: type string·number·integer·boolean·list·map·json, items·min·max·enum·labelKo·labelEn) + `check_param` — **50 에이전트 81 키** 선언(엔진 기본값 사본). 실행 상태 값(now·usage·dailySpent·recentCalls·peer·attachments 등)은 선언하지 않음
- 정책 `spec.agentParams.<id>`·`spec.relocated`·`spec.budgets`(costPer1k·monthlyBudget·alertRatio·overStreak) — `check_refs`(선언 키·형·범위·없는 에이전트·인라인만 재배치) → 배포·시험·시뮬레이터 초안·롤백 모두 검증. 빈 값은 본문에서 빼서 기존 버전과 같은 본문이면 새 버전 없음
- 관문 병합 `orchestrator.agent_request` — strict(실제 관문 경로: judge:batch·stream·단일 판정·시뮬레이터·정책 단위 시험·상시 점검): 선언된 키의 호출자 값 버림 + 정책 값. 코퍼스 재생(판정 미리보기·설정 영향)은 표본 시나리오 params 유지 + 정책 값 우선
- 재배치: `gating.run` 이 relocated 를 인라인에서 빼고 `run_relocated` 가 응답 뒤 `_POOL` 에서 판정 → 유효 판정 최대 alert, Finding + 원장 `gate_async`. 적용·복귀 = 승인 행동 `gate_relocate`/`gate_restore`(2인) → 정책 새 버전. 무시 = 원장 `gate_ops relocation_ignored`(사유)
- API: `GET/POST/PUT /v1/agents/{id}/config{,:test}` · `GET /v1/gates/{gate}` · `GET /v1/gates/degradation` · `GET /v1/gates:status` · `POST /v1/gates/{gate}/relocations{,:ignore}` · worker 매시 `gates.slo_check` → 원장 `slo`(테넌트별) → 알림 센터 '비용·SLO'
- 콘솔: `components/AgentSettings`(선언 기반 폼 — 변경 시험(단위 시험·골든/공격 코퍼스 영향·표본 판정·diff) 통과 + 사유 후에만 배포) → `/catalog/[id]`·`/extended/[x]`; `/gates/[gate]`(SCR-D02: 기간 탭·KPI 5·에이전트 표·지연 분포·비용·SLO·재배치 제안 적용/무시·복귀); `/gates/degradation`(SCR-D06: 닫기 없는 강등 배너·현재 강등·경보 전용·실패 모드 표·자동 강등 규칙·failMode 표·강등 이력); 상단 바 관문 칩(CMP-15: degraded-closed 적색·open 주황, 클릭 → D02)·셸 강등 배너. x04 시험 표본은 등록부를 요청 params 로 넘기지 않음(정책 설정으로)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T27-01 | PASS | 80 매니페스트 검증, 81 키 기본값 형 일치 (api 컨테이너), coverage 80/80 |
| T27-02 | PASS | logs/api-smoke.txt — garam: 정책 없음 + 호출자 넓힘 → block · PUT 후 allow · 호출자가 [] 로 좁혀도 allow · 원복 후 block (pytest: 호출자가 evil.example 추가해도 block) |
| T27-03 | PASS | 형 불일치·미선언 키·사유 없음 422, autonomyLevel 9 422, YAML 배포 미선언 키 422, relocated 상시 계열(d7-02) 422 |
| T27-04 | PASS | 허용목록에 evil.example 추가 시험 → 단위 시험 2/2 · 공격 탐지 10 → 4 · 표본 block → allow · diff, 정책 버전 그대로 |
| T27-05 | PASS | default@v5 → v6 (원장 note “agent config d1-06: E2E 사내 CDN”), 같은 값 재배포 changed=false, 원복 v7 |
| T27-06 | PASS | pytest — 초안 agentParams 로 재실행, changed [{d1-06 block → allow}] |
| T27-07 | PASS | 요청 → appr.one·appr.two 승인 → 판정 allow · relocated [d1-06] → 비동기 Finding (d1-06, block, 유효 alert) → 복귀 승인 → block |
| T27-08 | PASS | /v1/gates/output — records·p95·에이전트 8·히스토그램 8구간·제안·cost null(단가 미설정) |
| T27-09 | PASS | degradation 구성요소 5·failMode 80·DP5 위반 0, gates:status 3관문 |
| T27-10 | PASS | pytest — budgets(costPer1k 1000·월 1원) → slo_check 비용 경보 → /v1/notifications '비용·SLO' → /gates/output |
| T27-11 | PASS | logs/e2e-d02.txt·d02-ko.png — KPI(p95 65.7ms·44%·타임아웃 600ms·판정 67·비용 단가 미설정·오탐 0.21%), d4-01 초과(적색)·제안, 무시 → “무시 — 원장 #63940 에 사유 기록”, 7일 탭, 콘솔 오류 0 |
| T27-12 | PASS | logs/e2e-d06-settings.txt·d06-ko.png — 칩 output=degraded-closed, 셸 배너, 페이지 배너(닫기 버튼 0), 현재 강등 d4-01 closed·타임아웃 7%, 실패 모드 표 '강등 1건', 이력 seq 64135–64175 진행 중 |
| T27-13 | PASS | /catalog/d1-06 — 시험 전·사유 없음 배포 비활성, 시험 결과(단위 2/2·코퍼스 표·diff), 배포 → '정책 값' 배지, 원복 → default@v11 |
| T27-14 | PASS | 338 passed · vitest 14 · tsc 0 · 영어 11 경로 새 문구 한글 0(남은 것: 에이전트 매니페스트 규칙 설명) · 한국어 9 경로 콘솔 오류 0 |

## 회차 / Rounds
- round 1: pytest 6/8 — `gates.detail` 재배치 목록이 활성 바인딩에만 의존 → 정책 relocated 전체(관문 일치)로, `dict(s.execute(...))` → `.all()` → 9/9
- round 2: 전체 회귀 1 실패(test_policy_ops diff — 원복 버전이 첫 버전과 같은 본문) → 다른 본문 버전과 비교
- round 3: E2E 부하 생성기가 `judge` 바깥에서 지연 → 에이전트 latencyMs 에 안 잡힘 → `detect` 안쪽으로, 강등 모사는 d4-01 20ms + 하드 타임아웃 5ms

## 남은 것 / Notes
- 부하·강등 모사는 api 컨테이너 안 in-process TestClient(실제 관문 경로·로컬 DB)로 만든 기록이다. 실제 느린 에이전트는 없다.
- 방어 비용은 정책 spec.budgets.costPer1k(단가)를 넣어야 계산한다 — 추정치를 만들지 않는다.
