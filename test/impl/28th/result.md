# 시험 결과 / Test Result — impl 28th (Epic 28 D1·D2 상세 화면)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 12, 통과 12, 실패 0 → 최종 **PASS** (재시도 2회: 시험 표본 엔트로피·삭제 유예 기대값 / 재현 시험 표본 분리가 폼 제출의 CRLF 를 못 나눔)
- `make test` **347 passed** (+ test_domains_d1d2 9) · `make test-web` 14 + tsc 0 · 변경 에이전트 12종 골든/공격 재생 오탐 0·탐지 1.0
- 화면: `/domains/d1/{goal-jailbreak,exfil}` · `/domains/d1/inspect/{finding}` · `/domains/d2/{pii,isolation,erasure}` + D1·D2 개요의 상세 링크

## 구현
- 공통: `POST /v1/agents/{id}:inspect`(정책 병합 strict, 엔진 신호·`explain`·이중 판정(엔진 2개 이상일 때), 저장 없음) · 엔진 `EngineAdapter.explain` 훅 · 판정 기록 `shape`(원문 없이 구조만) · 설정 API `overrides`(이 항목 규칙만, 통째 교체) · 콘솔 `Inspector`/`ExplainView`(kind 별 표·타임라인)·`AgentSettings` 규칙 재정의 표·`/domains/[d]/[view]` 디스패처 + `lib/domainScreens`
- 에이전트: explain 추가 d1-01·02·03·04·05·06·07·d2-01·02·04·05(판정 불변). 동작 변경(1.1.0): d1-06 blockAutoRender·entropyBits, d1-07 matchOutput·similarityThreshold, d2-01 신뢰 구역(zonePolicy·params.zone, raw·last4·mask·pseudo·block, 외부 모델 기본 금지 → D2-01.zone-block), d2-07 defaultTtlDays + memory 저장소, d2-05 release_gate(maxExtractionRate·maxMiaAuc·maxDpEpsilon). 새 표본 run5.jsonl(d2-01 공격 2·골든 1, d1-06 골든 1, d2-07 공격 1)
- 집계 `app/domains.py`(입력 검사·허용목록 이력·설계 원칙 위반·접근 결정·지점별 자격증명·교차 조회 회귀), `app/privacy.py`(삭제 요청 = 원장 erasure: 해시 식별자·저장소 보고·D2-07 재검사(상시 점검 경로)·증적 발행 / 재현 시험 = 원장 recall_test, 출력 표본 미저장), 권한 `privacy`, `GET /v1/redteam/campaigns?agent=`(에이전트별 결과)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T28-01 | PASS | d1-05 비가시 12·해독 “ignore rules”·U+E0069…, d1-02 [allow, allow, require_approval]·sha256 64자, d1-03 dev-mode·override ≥0.88, d1-01 S0 데이터 전용·override, Finding 수 변화 0 |
| T28-02 | PASS | transform→allow(렌더 차단 끔), transform→block(엔트로피 2.0, “aabbccddeeffgghh” 3.0 bits), block→allow(대조 끔), 카나리 가림 “AEGIS-…12” |
| T28-03 | PASS | external_model → D2-01.zone-block · agent_screen: “010-1234-5678” 원문·주민번호 끝 “568” 만, explain 모드 {rrn: last4, phone: raw} |
| T28-04 | PASS | overrides 반영·기존 항목 유지·D1-06 키 422·원복 |
| T28-05 | PASS | shape.text 4·세그먼트 [(web, untrusted, 근거), (tool, trusted, —)]·형제 판정 1, 원장 gate 본문에 “상품 소개” 없음 |
| T28-06 | PASS | cdn(vN) < docs(vN+1) |
| T28-07 | PASS | tenant·user·session 0/20 (API) · 0/100 (화면, 원장 #65753), kang(dev-copilot) hr/salary deny·kb/fee allow |
| T28-08 | PASS | API·화면 — cache 실패 → block(잔존 cache, backup 은 유예 내 저점수) → 복구 → 통과(alert = 증적 미발행 경보) → 발행 원장 #65763, 식별자 원문 원장에 없음, 발행 후 보고 409, 개발자 403 |
| T28-09 | PASS | 설정 없음 409 · 카나리 재현 1/10 + AUC 0.66 → 차단(사유 2) · 정상 20건 → 통과 · 화면 v4 차단(1/1)·v5 통과(0/3 — CRLF 분리 수정 후) |
| T28-10 | PASS | logs/e2e.txt · e02·e03·e04·f02·f03·f04-ko.png — 검사기 실행·규칙 재정의 표(d1-02 2·d1-03 11·d2-01 7)·카나리 생성·구역 표·파이프라인·회귀 실행·삭제 흐름·재현 시험, 콘솔 오류 0 |
| T28-11 | PASS | logs/en-sweep.txt — D1·D2 개요·erasure 한글 0, 나머지 남은 한글 = 에이전트 규칙 설명(매니페스트)·판정 근거 메모(데이터). ko 8 경로 오류 0 |
| T28-12 | PASS | 347 passed · vitest 14 · tsc 0 · 골든/공격 재생 12종 |

## 회차 / Rounds
- round 1: 엔트로피 시험 표본이 2.0 bits 미만 → 3.0 bits 표본으로, 삭제 흐름 기대값(백업 실패 = 유예 내 저점수) → 캐시 실패로 차단 확인
- round 2: 재현 시험 표본 분리 — 폼 제출이 줄바꿈을 CRLF 로 바꿔 `\n\n` 분리가 안 됨 → `\r?\n` 허용

## 남은 것 / Notes
- 외부 연동이 필요한 구성요소는 정직하게 표시: 분류기 이중 판정(내장 엔진 1개 → “이중 판정 없음”), 검색 전 관계 기반 인가(OpenFGA) 없음 → 후단 재검증, 이그레스 프록시 없음 → 출력 관문, 멤버십 추론·차등 프라이버시 = 외부 시험 결과 입력.
- 카나리·학습 카나리는 정책 본문(원장)에 들어간다 — 미끼 문자열만 쓰도록 화면에 안내.
