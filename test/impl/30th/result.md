# 시험 결과 / Test Result — impl 30th (Epic 30 D5·D6 상세 화면)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (재시도 2회: 규칙 설명 자동 삽입이 d5-06 의 다른 RULES 구문을 깨뜨림 → KINDS 로 / 시험 기대값(계약 값 중첩))
- `make test` **357 passed** (+ test_domains_d5d6 5) · `make test-web` 14 + tsc 0 · **80 에이전트 전체** 골든/공격 재생 문제 0
- 측정: 토큰 2종 중 재사용 1(노드 2·세션 2)·aud 불일치 1 · 장치 지문 변경 1 · 위임 교집합 밖 deploy:prod 차단 · 드리프트 점검 주체 2·발견 1 · 계보 6단계(e90 반복) 차단 → 강제 종료(격리 qtn_88c0…) · 이체 ₩2,400,000 승인 대기 → appr.one 1/2

## 구현
- 보호 대상별 계약 `byPrincipal` — `orchestrator.agent_request` 병합(주체 계약 > 공통 > 엔진 기본, 호출자 값 무시 유지), `policy.check_refs` 검증, 설정 API `?principal=`·`ConfigIn.principal`(공통 값과 분리 저장), 콘솔 `SettingsCard principal`
- 엔진(1.1.0): d5-06 requireAudience(audience-missing 차단), d6-04 계약(contract 우선, maxSubtasks), d6-07 requireCompensation·compensations(no-compensation 차단). explain: d5-01~07·d6-01~07(판정 불변). 새 표본 3건
- 요청 모양: principalMeta·agentMeta(유형·역할·범위), auth(method·mfa·signed·attested·aud·azp·lifetimeSec·exp·jti 해시·cnf), sessionMeta(bound·fpChanged·ipChanged·IP/지문 해시), history 요약, resource
- 집계·API: `/v1/domains/d5/{identity,tokens,authz}` · `POST /v1/domains/d5/authz:drift-scan`(관측 인벤토리 → D5-07 상시 점검 경로) · `/v1/domains/d6/{autonomy,runs,runs/{trace},budgets}`
- 콘솔: `/domains/d5/{identity,tokens,authz}`, `/domains/d6/{autonomy,lineage,budgets}`, `/domains/d6/lineage/[trace]`(계보 트리·상태 해시·상한(대상)·강제 종료), 지출 2인 승인 카드(같은 화면에서 결정), 검사기 진단 렌더러 14종 추가

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T30-01 | PASS | loan-review: draft.save(medium) 승인 요구 / other: allow, 공통 2 배포 후에도 대상 0 유지, crm.export 차단·계획 3 > 2 승인, 미선언 키 422 (pytest) · 화면에서 대상 계약 배포 default@v19 → 레벨 0 표시 |
| T30-02 | PASS | D5-06.audience-missing · bearer, D6-07.no-compensation / remit 등록 시 allow, d6-01 explain 등급 I2 > 레벨 1 |
| T30-03 | PASS | batch-report 토큰 reuse(노드 2·세션 2)·lifetime 300 · jti 해시 8자, 응답에 IP·jti 원값 없음 · 화면 KPI 재사용 2·이상 1 |
| T30-04 | PASS | effective [repo:read]·outside [repo:write] 차단, kang 미사용 repo:admin · drift-scan D5-07.unused-privileged · 화면 “드리프트 점검 — 주체 2 · alert · 발견 1건” |
| T30-05 | PASS | 노드 planner→coder, 상태 해시 3번째 반복 표시, limits d6-03, 404 · 지출 loan-review-agent 대기 ₩2,400,000 · 승인 카드 apr_c404… |
| T30-06 | PASS | logs/e2e.txt · i02(플랫폼 SVID 84 유효)·i03·i04·j02·j03·j04-ko.png — 테넌트 사용자 SVID 표 = 권한 안내, 강제 종료 메시지, appr.one 승인 1/2 후 같은 화면 복귀, 콘솔 오류 0 |
| T30-07 | PASS | logs/en-sweep.txt — 화면 문구 한글 0, 남은 한글 = 판정 근거 메모(에이전트 데이터) · ko 7 경로 오류 0 |
| T30-08 | PASS | 357 passed · vitest 14 · tsc 0 · 80/80 재생 |

## 회차 / Rounds
- round 1: 규칙 설명을 core 의 `"…pass"` 앞에 끼우는 스크립트가 d5-06(RULES 를 KINDS 로 생성하는 구조)을 깨뜨림 → KINDS 에 추가로 바로잡고 80 에이전트 전체 적재·재생 확인
- round 2: 계약 값은 agentParams 구조 그대로(`{"contract": {...}}`) — 시험 기대값 수정

## 남은 것 / Notes
- 시험용 계약(d5-06 audience, d6-01 loan-review-agent)은 시험 뒤 원복(v20·v21). 강제 종료한 `e2e-runner` 는 격리 목록에 남아 있다(시험 주체).
- 내구 실행 재개(Temporal 체크포인트)·API 게이트웨이 쿼터 집행·IdP 권한 회수는 외부 시스템 몫 — 화면은 판정·관측·제안·원장 기록까지.
