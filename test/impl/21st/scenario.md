# 시험 시나리오 / Test Scenario — impl 21st (Epic 21 첫 실행 마법사 ②~⑤ + 설치 검증)
- 근거: NFR-O1(설치 후 30분 안에 첫 판정) · SCR-A07 신원·비밀 · SCR-A08 증적·관측 · SCR-A09 대상·첫 판정 · SCR-A10 설치 검증
- 환경: local compose(SQLite, api·web·worker·otel-collector) · 계정 plat.admin(시험 값, logs/e2e-credentials.env)

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T21-01 | 단계 실측 | `GET /v1/setup/status` | 단계 5개(관리자·신원·증적·첫 판정·검증) 완료 여부를 실데이터로, 설치 후 경과·첫 판정까지 분(음수 없음, 설치 이전 판정 제외)·목표 30 | P0 |
| T21-02 | 설치 검증 | `POST /v1/setup/verify` | 입력·도구·출력 관문 실제 경로 도달 + 증적 적재, 기동 검사 4종(격리·서명·강등 기본값·누락), 사전 점검, 원장 `setup` 기록 | P0 |
| T21-03 | 권한 | tenant_admin·security_engineer 가 verify | 403 (플랫폼 관리자 전용) | P0 |
| T21-04 | 접근 제어 | 비로그인 `/setup/identity` | `/login?next=…` · `/setup`(부트스트랩)만 공개 | P0 |
| T21-05 | A07 화면 | `/setup/identity` | SVID 수명·회전·유효 수, 비밀 백엔드, 정적 키 탐지(0 ✓), 단계 표시·경과 | P1 |
| T21-06 | A08 화면 | 보존 365 저장 → 90 복원 | 기본 테넌트 보존 변경 + 원장 기록 배너, 원문 보존 꺼짐·국외 이전 deny, OTel 파이프라인 | P1 |
| T21-07 | A09 첫 판정 | 대상·프로파일·표본 → 시험 요청 | 프로파일 적용 + judge:batch → 판정·에이전트·근거·trace, 위험 없으면 그대로 표시 | P0 |
| T21-08 | A10 다시 검증 | 버튼 | 관문 3/3 · 기동 4/4 · 사전 점검 8/8 · 단계 5/5 | P0 |
| T21-09 | 회귀 | `make test` · `make test-web` | 전부 통과 · 콘솔 오류 0 | P0 |
