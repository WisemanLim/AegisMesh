# 시험 결과 / Test Result — impl 40th (Epic 40 영어 런북·규칙 설명 · en 화면 한글 0)
- 일자: 2026-10-07 · 대상: local compose + Playwright(en 회차 한글 측정) · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 3회: 세션 끊김(봉인 키 이전 과도기) / 사이드바·아바타 / 판정 근거 메모·확장 예시) · 회귀 2회(run-r4·r5)
- `pytest` 388 passed(OpenBao 시험 제외 — 41차) · `make test-web` 15 + tsc · en 관문 8틀 26쪽 한글 0 · 접근성 146쪽 위반 0 · 키보드·입력 목적 46/46
- 측정으로 찾은 결함: **사이드바 확장(X) 항목 이름이 두 번 표시**(ko·en 모두 "X01 에이전트 간 통신 X01 에이전트 간 통신"), 카탈로그·판정 상세의 규칙 설명과 엔진 근거 메모가 en 에서도 한국어

## 구현
- `runbooks/en/*.md` 11종 · `app/incidents.py` `runbookTextEn`
- `agents/*/rules.en.yaml` 80개(규칙 378) · `aegis/agent.py` `rules_en`·`explain_rule(rule, lang)` · MCP `explain(rule_id, lang)` · API `rulesEn`(에이전트·설정) · `ruleDescriptionEn`(판정)
- `apps/web/lib/en.ts` 엔진 근거 메모·엔진 설명 309 패턴 · 카탈로그·확장·사건·판정·설정 표가 en 이면 영어 사용 · 도메인 화면 근거 메모·서버 메시지 `LX` 50곳 · Shell 확장 항목 이름 중복 수정 · 아바타 첫 글자도 번역 이름 기준 · X06 예시 입력 영어
- 측정: `test/e2e/a11y_e2e.py` en 회차 한글 수집(`data-user` 제외) + 관문 8틀 판정 · `test/test_english.py` 4 · vitest 근거 메모 패턴 1

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T40-01 | PASS | 11종(d1~d10·x) 파일·단계 수 일치, 한글 0 |
| T40-02 | PASS | 80 에이전트 · 378 규칙 키 일치 · 한글 0 (pytest) |
| T40-03 | PASS | d3-03 rulesEn · 판정 ruleDescriptionEn · 설정 rulesEn · 사건 runbookTextEn "# Runbook — D3 tool misuse incident" · explain("D1-05.alt-text","en") |
| T40-04 | PASS | "규칙 5종 검사 통과" → "Passed 5 rule checks", "허용 루트 /workspace 밖 쓰기" → "write outside the allowed root /workspace" 등 · 카탈로그 전체 자리표시·한글 검사 통과 |
| T40-05 | PASS | /incidents 1 · /incidents/[id] 4 · 대응 2 · /catalog 1 · /catalog/[id] 6 · /findings 1 · /findings/[id] 8 · /extended/[x] 4 — 한글 0 (run-r3·r4·r5) |
| T40-06 | PASS | 146쪽 serious·critical 0 · 46/46 |

## 회차 / Rounds
- round 1: 측정 도중 `session lost` — 39차에서 봉인 키 위치를 바꾼 뒤 HMR 로 기존 프로세스가 옛 키(메모리)를 계속 쓰다가 dev 재시작 때 새 위치 키로 바뀐 과도기. 이후 재시작에도 같은 키 유지(재발 없음)
- round 2: 사이드바 확장 항목 이름 중복·아바타 첫 글자 "플" → 수정. 남은 것: 판정 상세 규칙 설명·근거 메모, X06 예시 입력
- round 3: `ruleDescriptionEn` + 엔진 근거 메모 309 패턴 + 예시 영어 → 관문 8틀 한글 0
- round 4 (run-r4): 판정 상세 외 화면의 근거 메모 `LX`(Tray·Inspector·inspect·grounding·calls·d2·d4·d8 15곳) 뒤 회귀 PASS — 관문 밖 en 한글 22쪽·183노드
- round 5 (run-r5): 도메인 화면 근거 메모 목록·서버 메시지 `LX` 50곳 뒤 회귀 PASS — 관문 밖 19쪽·168노드

## 남은 것 / Notes
- 관문 밖 도메인 상세 화면(en)에 한글 168노드가 남는다(run-r5, en 72쪽 중 19쪽): 예시 입력 JSON 10쪽(시험용 한국어 프롬프트 — 입력 데이터), 근거 메모를 다른 필드로 그리는 표(d7 검토 101 · d7 무결성 10 · d5 토큰 15 · d9 3화면 20 · d7 SBOM 5 등). 다음 차수 후보.
- 판정 근거 메모는 저장된 한국어 원문을 표시 시 번역한다 — 카탈로그에 없는 새 메모는 한국어로 보인다(vitest 가 값·자리표시만 보장).
