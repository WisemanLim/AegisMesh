# 15차 시나리오 — Epic 15 관측 OTel

근거: FR-P09(지표·추적·로그 OpenTelemetry 규약 + 수집 단계 마스킹), NFR-O3(벤더 형식 강제 금지), FR-D10-07, D2-06,
SCR-Q04(SLO·비용·오탐 예산), SCR-Q05(관측 파이프라인·마스킹 설정 — 규칙은 시험 로그로 확인 후 배포).

| id | 목적 | 입력 | 기대 | 우선 |
|---|---|---|---|---|
| T15-01 | 수집기 기동 | compose `otel-collector` (contrib 0.162.0) | 설정 검증 OK, “Everything is ready”, api·worker 내보내기 활성 | P0 |
| T15-02 | 관문 추적 = 판정 traceId | `judge:batch` (입력 관문) | 수집기에 `aegis.gate.input` span, trace id = 응답 traceId, 에이전트 하위 span | P0 |
| T15-03 | 원문 미전송 | 카드번호 포함 요청 | 수집기 출력에 원문 없음 (규칙·판정·위치만) | P0 |
| T15-04 | 수집 단계 마스킹 | 시험 로그(이메일·전화·카드·주민번호·키) 전송 | 수집기 출력은 [REDACTED_*], 원문 0건 | P0 |
| T15-05 | 지표·로그 | 판정 후 15초 | aegis.gate.requests·duration·findings 지표, finding 로그 | P1 |
| T15-06 | 규칙 단일 원천 | `gen_otel_config.py --check`, 규칙 시험 | 생성물 최신, 표본 치환·보존 예 유지, RE2 호환 | P1 |
| T15-07 | D10-07 해소 | 거버넌스 자체 점검 | `D10-07.no-collector` 없음 | P1 |
| T15-08 | 콘솔 /observability | 파이프라인·마스킹 규칙·시험 로그·SLO·오탐 예산 | 렌더, 미리보기·전송 동작, 콘솔 오류 0 | P1 |
| T15-09 | 회귀 | `make test`, `make test-web`, coverage, prod 리허설 | 통과 | P0 |
