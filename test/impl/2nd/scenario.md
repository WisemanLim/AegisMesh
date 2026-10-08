# 시험 시나리오 — impl 2nd · Epic 2 레지스트리·데이터

근거: PRD §11.3(R1)·§12.2·§12.3·§12.6, FR-P03·P16, DP1·DP9, COMPLIANCE 추가 시험(OpenAPI 계약).

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| U-01 | 시드 (도식 80·내장 에이전트) | migrate + seed, 재실행 | risk_items 80, 멱등 | P0 |
| U-02 | 위험 지도 API | GET /v1/risk-items | 80 항목, 상태(available/missing), D1→D10→X 순서 | P0 |
| U-03 | 카탈로그·상세 | GET /v1/agents, /v1/agents/d1-05 | 매니페스트 + 실측 품질 + 규칙 | P0 |
| U-04 | 등록 R1 거부 | 스키마 오류, 의존성, 내장 충돌 | 422 + 단계 R1 | P0 |
| U-05 | 등록 YAML·심사 대기 | application/yaml 매니페스트 | 201 review_pending + agent 증적 | P0 |
| U-06 | 커버리지 API | GET /v1/coverage | total 80, strict 19 | P0 |
| U-07 | 원장 추가 전용 (SQLite 트리거) | UPDATE·DELETE evidence | append-only 오류 | P0 |
| F-01 | local 자동 마이그레이션·시드 | make local-all + curl | health ok, risk-items 80 | P0 |
| F-02 | prod 마이그레이션 (Postgres) | make prod-build → db-migrate → db-seed ENV=prod | exit 0, alembic 0002, 시드 80·3 | P0 |
| F-03 | prod API | /health, /v1/agents, POST 잘못된 매니페스트 | postgres ok, 3 active, 422 | P0 |
| F-04 | 원장 추가 전용 (Postgres 트리거) | UPDATE·DELETE·TRUNCATE | 모두 append-only 오류 | P0 |
