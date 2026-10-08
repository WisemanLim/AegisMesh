# 시험 시나리오 — impl 3rd · Epic 3 관문·오케스트레이션·정책·프로파일

근거: PRD §8.2·§8.6·§11.1·§11.4·§15.3, FR-P01·P02·P04·P15, DP5·DP6, NFR-A2·A3·L1~L3·Q4·D1.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| U-01 | 프로파일 5종·순서·extends 해석 | GET /v1/profiles, regulated-kr | 5종 순서, chatbot ⊂ tool ⊂ regulated, full-mesh 80 | P0 |
| U-02 | 적용 → 바인딩 + 증적 | :apply chatbot-baseline | 3 agents, profile 증적(by) | P0 |
| U-03 | 입력 관문 차단 + 판정 조회 | 태그 블록 | block, 근거·원장·규칙 설명 | P0 |
| U-04 | 출력 관문 합성 + transform 연쇄 | 카나리+키 | block(d1-07) + transform(d2-03), 마스킹 결과 | P0 |
| U-05 | 원문·무해화 결과 미보존 (NFR-D1) | 키 포함 출력 | 저장 Finding 에 transform 없음, 원장에 키 없음 | P0 |
| U-06 | 적용 단계 3종 (관측/부분/전체) | 0.97·0.82 신뢰도 | observe alert, partial 0.9 기준, enforce block | P0 |
| U-07 | 정책 버전 (DP6) | POST /v1/policies 2회 | v1→v2, minConfidence 적용, 잘못된 문서 422 | P0 |
| U-08 | 정책 override·alert_only | 단위 | threshold 경계, 경보 전용 강등 | P1 |
| U-09 | 타임아웃 강등 (DP5·FR-P15) | 300ms 지연 에이전트 | C1 block, C3 allow, 강등 증적 | P0 |
| U-10 | 재현성 (NFR-Q4) | 동일 입력 3회 | 동일 판정·규칙 | P0 |
| U-11 | 단일 판정 경로 | /v1/judge?agent= | M1 과 같은 본문, 없는/미심사 에이전트 404·409 | P0 |
| U-12 | 오류·해제 | 프로파일 없음, 잘못된 관문, 해제 | 409·404·422, 해제 후 409 | P1 |
| F-01 | 실서버 적용 | curl :apply | enforce, 3 agents, missing 11 | P0 |
| F-02 | 실서버 관문 판정 | 입력 공격·출력 키 | block / transform 마스킹 | P0 |
| F-03 | 관문 지연 (NFR-L1·L3) | 입력·출력 관문 각 200회 | p95 < 80ms / 150ms | P0 |
