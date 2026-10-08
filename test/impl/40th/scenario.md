# 시험 시나리오 / Test Scenario — impl 40th (Epic 40 영어 런북·규칙 설명 · en 화면 한글 0)
- 근거: 원본 PRD NFR-C4(콘솔·문서 한/영) · 계획표 40 수용 기준 "런북 10종·규칙 설명 en, en 모드 사건·카탈로그·판정 화면 한글 0(사용자 데이터 제외)".
- 방식:
  - 런북 — `runbooks/en/*.md`(원문 `runbooks/*.md` 11종과 같은 단계 수). 사건 상세 API `runbookTextEn`, 콘솔 en 이면 영어 런북.
  - 규칙 설명 — 에이전트 번들 안 `rules.en.yaml`(데이터 파일, 코드 실행 없음) → 런타임 `rules_en`. API `/v1/agents/{id}` `rulesEn` · `/v1/agents/{id}/config` `rulesEn` · `/v1/findings/{id}` `ruleDescriptionEn` · MCP `explain(rule_id, lang="en")`. 한국어가 원문, 빠지면 한국어로 대체.
  - 엔진 근거 메모 — 저장된 판정의 메모(한국어)를 콘솔 카탈로그(`lib/en.ts`, {n} 패턴)로 표시 시 번역 — 과거 판정에도 적용.
  - 판정 — `make e2e-a11y` en 회차에서 화면 글자(사용자 데이터 표시 `data-user` 제외)의 한글 수. 관문 틀: /incidents · /incidents/[id] · /incidents/[id]/response · /catalog · /catalog/[id] · /findings · /findings/[id] · /extended/[x].
- 환경: local compose · plat.admin · 시작 경로 /incidents,/catalog,/findings,/extended/x01 (동적 링크 추적: 판정 8 · 사건 4 · 대응 2 · 카탈로그 6 · 확장 4)

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T40-01 | 영어 런북 | runbooks/en 11종 | 원문과 같은 파일·단계 수, 한글 0 | P0 |
| T40-02 | 규칙 설명 영어 | 내장 에이전트 80종 | rules_en 키 = rules 키(378), 한글 0 | P0 |
| T40-03 | API·MCP | agents/{id} · findings/{id} · config · 사건 상세 · MCP explain | rulesEn · ruleDescriptionEn · runbookTextEn · explain(en) | P0 |
| T40-04 | 엔진 근거 메모 | 엔진 표시 문구 309종 | 카탈로그 패턴 번역(중첩 조각 포함), 값에 한글 0·자리표시 일치 | P1 |
| T40-05 | en 화면 한글 0 | 관문 8틀 26쪽 | 한글 0 | P0 |
| T40-06 | 회귀 | 접근성·키보드 | serious·critical 0, 키보드·입력 목적 PASS | P1 |
