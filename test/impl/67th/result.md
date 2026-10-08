# 시험 결과 / Test Result — impl 67th (Epic 67 agentgateway 연동)
- 일자: 2026-10-08 · 대상: local · agentgateway v1.6.0 (`cr.agentgateway.dev/agentgateway@sha256:9d3e6044…`, 2026-10-02) · ExtMCP 프로토콜 `crates/protos/proto/ext_mcp.proto`@v1.6.0 (sha256 4ba750cc…) · 커밋: —

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 1회: 첫 차단 판정이 dev 서버 재기동 직후 3 s 초과 → 정책 서버 시간 한도로 failClosed — 재실행 9~58 ms)
- MCP `tools/call` 이 게이트웨이에서 **AegisMesh 도구 관문**(요청)·**출력 관문**(결과)을 거친다: 허용 → 실행 · 위험 명령 차단(D3-03·D3-07) · 고액 이체 승인 요청(D3-01·D6-07, `apr_…`)·한도 초과 차단 · 결과 속 키 `[REDACTED_AWS_ACCESS_KEY]` 치환
- 정책 서버가 없으면 허용 도구도 거부(failClosed) · 원장에 관문 기록 137건(target agw.demo), 원문 미보관 · 허용 호출 왕복 p50 23 / p95 98 ms(게이트웨이 + 두 관문 + 시연 MCP)

## 구현
- `infra/agentgateway/config.yaml` — `mcp.policies.mcpGuardrails`: remote `extmcp:9001`, `failureMode: failClosed`, `tools/call: full`(요청·응답), 대상 = 시연 MCP(Streamable HTTP)
- `infra/extmcp/`(Dockerfile + server.py) — gRPC `agentgateway.dev.ext_mcp.ExtMcp`(빌드 때 고정 proto → 코드 생성, grpcio 1.75.1·protobuf 6.32.1). CheckRequest: 도구 이름·인자 → `POST /v1/judge:batch` gate=tool(주체 = `x-aegis-principal` 헤더) → block/require_approval 이면 `PERMISSION_DENIED`(규칙·승인 ID·trace), CheckResponse: 텍스트 내용 → gate=output → transform 이면 `mutated` result. AegisMesh 실패 = gRPC UNAVAILABLE → 게이트웨이 failClosed
- `infra/agentgateway/mcp_demo.py` — 표준 라이브러리 MCP 서버(도구 4종, 흉내만 — 셸·이체 없음)
- `app/agw.py` setup — 서비스 계정 `svc.agentgateway` 토큰(24 h, 비커밋 `infra/agentgateway/extmcp.env` 600) + `agw.demo` 에 `tool-agent` 프로파일(enforce)
- compose local 프로파일 `agw`(agentgateway 127.0.0.1:`AGW_PORT`=3100 · extmcp · mcp-demo, 모두 read_only) · `make agw-up|agw-down` · `test/test_agw.py` 2건

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `c01-agw-up.txt` · `--validate-only` 엄격(모르는 필드·단계 거부 확인) |
| C02 | PASS | `c02-e2e.txt` serverInfo aegis-mcp-demo · 세션 ID · 도구 4 |
| C03 | PASS | isError=False 검색 결과 |
| C04 | PASS | isError=True `AegisMesh 도구 관문 차단 — D3-03.privilege-cmd, D3-07.code-exec (trace …)` — 시연 서버 응답 아님(업스트림 미도달) |
| C05 | PASS | `승인 필요 — D3-01.high-risk-tool, D6-07.needs-approval · 승인 요청 apr_b3f8abdd77fc` / 99,000,000 = `D6-07.over-limit` 차단 |
| C06 | PASS | `연동 키 [REDACTED_AWS_ACCESS_KEY]` |
| C07 | PASS | 30건 p50 23.0 / p95 97.5 ms |
| C08 | PASS | `c03-failclosed.txt` 중단 중 `mcpGuardrails checkRequest failed: upstream call timeout` → 복귀 뒤 정상 |
| C09 | PASS | `c04-ledger.txt` tool allow 65·block 5·require_approval 2, output allow 63·transform 2 · 원문 없음 · 승인 요청 주체 agent.e2e |

## 회차 / Rounds
- round 1: 첫 run_shell 판정이 정책 서버 시간 한도(3 s)를 넘어 failClosed(로컬 스택을 막 다시 띄운 직후 첫 요청) — 같은 판정 직접 호출 7~17 ms, 재실행 9 ms

## 남은 것 / Notes
- local 프로파일만 — prod 는 extmcp → api 상호 TLS(클라이언트 인증서 잎)·게이트웨이 → extmcp TLS 를 더해야 한다
- 차단은 MCP 도구 결과(isError=true)로 돌아온다(agentgateway 의 ExtMCP 오류 매핑) — 클라이언트는 결과 텍스트로 규칙·승인 ID 를 본다
