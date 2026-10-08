# 시험 결과 / Test Result — impl 1st (Epic 1 에이전트 SDK·CLI)
- 일자: 2026-10-06 · 대상: aegismesh (python-fastapi, local=SQLite) · 커밋: — (git 아님)

## 요약 / Summary
- 전체 14 (pytest 22건 포함), 통과 14, 실패 0 → 최종 **PASS** (재시도 1회)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-09 | PASS | `make test` 22 passed (logs/make-test.txt) |
| F-01 | PASS | `block D1-05.unicode-tag` |
| F-02 | PASS | `200 transform D2-03.github-token token [REDACTED_GITHUB_TOKEN]` |
| F-03 | PASS | tools [explain, judge, list_rules], `block D1-07.canary` |
| F-04 | PASS | exit 1, `coverage: 전체 3/80 · 엄격 2/19` — 미구현 17종 정확히 검출 (E5 에서 19/19 목표) |
| F-05 | PASS | d1-05 C1/input/L0/closed, d1-07 C1/output, d2-03 C3/output/open |

품질 지표 (3회 반복): d1-05 golden 12·attacks 12, d1-07 10·10, d2-03 10·11 — 오탐 0, 탐지 1.0, p95 ≤ 0.02ms.

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | `ModuleNotFoundError: mcp.server.fastmcp` | 설치된 MCP Python SDK 가 2.3.0 — FastMCP 가 MCPServer 로 개명 | `mcp.server.mcpserver.MCPServer` 로 이전, `mcp>=2.3,<3` 고정 | round 2 PASS |

## 한계 / Notes
- 골든셋 규모가 작다(에이전트당 10~12건). NFR-Q1 목표는 주간 1만 건 재생 — 실트래픽 표본 축적 필요.
- `action.transform` 에 무해화 결과(입력 유래 텍스트)가 담긴다 → 원장 적재 시 제거(Epic 3·4 에서 처리).

## 첨부 / Logs
- logs/make-test.txt, f1-cli-run.txt, f2-rest-serve.txt, f3-mcp-stdio.txt, f4-coverage.txt, f5-list.txt
