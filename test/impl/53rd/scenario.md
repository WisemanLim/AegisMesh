# 53rd — SPIRE 연동 (Epic 53 · FR-P07 · 화면설계서 "워크로드 신원 — SPIRE")

근거: 화면설계서 ①워크로드 신원 — SPIRE(SVID 수명·회전), 기존 구현은 내장 발급자(Ed25519). 9차 범위 결정.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (test_spire: 등록·uid 선택자·폐기 삭제·ES256 발급/검증·변조 거부·즉시 회전·세대 aud·내장 토큰 호환·JWKS·상태·첫 발급 자동 등록·SPIRE 장애 503) | P0 |
| C02 | 기동·노드 증명 | `make spire-up` | server healthy, join token(별칭 node/api)으로 agent 증명, 신뢰 번들로 첫 연결부터 검증 | P0 |
| C03 | 등록 동기화 | `GET /v1/identity` | 활성 신원 수 = SPIRE 등록 항목 수, 선택자 unix:uid | P0 |
| C04 | 발급·검증·사용 | 서비스 계정 SVID 교환 → 검증 API → SVID 로 API 호출 | ES256·SPIRE kid, 유효, 200 | P0 |
| C05 | 즉시 회전·폐기 | `POST /v1/identity:rotate {force}` · 서비스 계정 비활성 | 옛 SVID 거부·새 SVID 유효 · 항목 삭제 | P0 |
| C06 | 되돌리기 | `make spire-down` | builtin 복귀, SPIRE 토큰 거부 | P1 |
