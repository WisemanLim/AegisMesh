# 67th — agentgateway 연동 (Epic 67 · PRD 의존성 '전용 인프라: agentgateway' · 9차 한계)

근거: PRD 는 MCP·A2A 트래픽을 agentgateway 같은 전용 게이트웨이 앞에 두는 배치를 상정한다. agentgateway v1.6.0 의 MCP 가드레일
(ExtMCP, gRPC — 요청 단계 `params`·응답 단계 `result` 를 정책 서버가 통과·변경·거부)을 AegisMesh 관문 판정으로 잇는다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 고정 판 | `make agw-up` | agentgateway v1.6.0 digest 고정, 프로토콜 정의 sha256 검증 빌드, 설정 엄격 검증 통과 | P0 |
| C02 | MCP 세션 | initialize · tools/list | 게이트웨이 경유 정상 | P0 |
| C03 | 허용 도구 | search_docs | 도구 관문 allow → 그대로 실행 | P0 |
| C04 | 위험 도구 차단 | run_shell `sudo su -` | 도구 관문 block → 업스트림에 가지 않고 오류 결과(규칙·trace) | P0 |
| C05 | 승인 필요 | transfer 2,000,000 / 99,000,000 | require_approval → 승인 요청 생성·거부 / 한도 초과 block | P0 |
| C06 | 도구 결과 무해화 | get_order ORD-7731(키 포함) | 출력 관문 transform → 결과 텍스트 치환(mutated) | P0 |
| C07 | 지연 | 허용 호출 30건 | 게이트웨이 + 두 관문 왕복 실측 | P1 |
| C08 | 정책 서버 장애 | extmcp 중지 | failClosed — 허용 도구도 거부, 복귀 뒤 정상 | P0 |
| C09 | 증적 | 원장 | 관문 기록(target agw.demo)·승인 요청(주체 헤더), 원문 미보관 | P0 |
