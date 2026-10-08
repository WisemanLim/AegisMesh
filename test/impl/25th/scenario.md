# 시험 시나리오 / Test Scenario — impl 25th (Epic 25 A2A 어댑터)
- 근거: PRD §12.4(A2A v1.0.1 — AgentCard 공개 + 태스크 기반 협력, 카드 서명 검증) · FR-X01(에이전트 간 상호 인증·메시지 무결성) · D5-04(신원 위장) · 어댑터 4종(CLI·REST·MCP·A2A)
- 규격: A2A v1.0 (a2a.proto) — JSON-RPC `SendMessage`·`GetTask`·`CancelTask`, `A2A-Version: 1.0`, `supportedInterfaces[{url, protocolBinding: JSONRPC, protocolVersion}]`, `signatures[{protected, signature}]`
- 환경: pytest(TestClient + 실제 하위 프로세스 서버) · 단일 파일 CLI(debian:bookworm-slim, 파이썬 없음) 두 컨테이너 · local 플랫폼(JWT-SVID 발급·X01)

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T25-01 | 서명 카드 | GET /.well-known/agent-card.json | v1.0 필드, protected 헤더 EdDSA·kid·jku, JWKS 로 검증, 변조·다른 키·서명 없음 실패 | P0 |
| T25-02 | SendMessage | text part · data part | TASK_STATE_COMPLETED, Finding 아티팩트, 입력 원문·무해화 결과 미보존, GetTask, CancelTask → 취소 불가 | P0 |
| T25-03 | 오류 | 버전 없음·0.3·v0.3 메서드·파일 part·messageId 없음·잘못된 요청·스트리밍 | -32009·-32601·-32005·-32602·-32004 | P0 |
| T25-04 | 호출자 인증 | --trust-jwks · SVID 없음/정상/aud·만료·다른 키·SPIFFE 아님 | 401(WWW-Authenticate) / 200 / 401 | P0 |
| T25-05 | X01 | v1.0 카드 서명·변조·신뢰 키 없음 | allow / bad-signature / untrusted-key | P0 |
| T25-06 | CLI | aegis serve --protocol a2a · a2a card·send | 신뢰 고정 없으면 거부, 고정 시 호출, 다른 키 거부 | P0 |
| T25-07 | 실환경 | 단일 파일 CLI 두 컨테이너 + 플랫폼 SVID | 카드 검증·401·block·allow, 플랫폼 X01 이 실제 카드 검증 | P0 |
| T25-08 | 회귀 | make test · test-web | 통과 | P0 |
