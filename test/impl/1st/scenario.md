# 시험 시나리오 — impl 1st · Epic 1 에이전트 SDK·CLI

근거: PRD §5.3·§8.3·§8.4·§11.2·§11.5·§12.1·§12.4, DP2·DP3·DP5·DP7·DP8·DP10, NFR-Q1~Q5·L4·A2·A3·D1, FR-P16.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| U-01 | 매니페스트 R1 검증 | 정상/의존성/표준 누락/판본 공백/잘못된 판정/잘못된 ID | 정상 통과, 나머지 ValidationError | P0 |
| U-02 | 계열별 failMode 기본값 | C1, C3 | closed / open | P0 |
| U-03 | 판정 설명 동반 (DP3·NFR-Q3) | 태그 블록 입력 | block + ruleId·evidence·confidence·판본 표준, 원문 미포함 | P0 |
| U-04 | evidence 없는 판정 무효 | core 가 빈 evidence 반환 | valid=false, C1 → block | P0 |
| U-05 | 에이전트 예외 강등 (NFR-A2) | core 예외 | C1 block / C3 allow, 강등 근거 기록 | P0 |
| U-06 | 격리 등급 미달 기동 거부 | isolation L2, 런타임 L0 | StartRefused, L2 런타임이면 기동 | P0 |
| U-07 | 품질 게이트 (NFR-Q1·Q2·Q4·Q5·L4) | 3종 golden·attacks 3회 반복 | 오탐 0, 미탐 ≤10%, 기준선 이상, 재현 100%, p95 < 30ms | P0 |
| U-08 | 어댑터 REST / MCP / CLI (in-process) | 판정 요청 | 동일 Finding | P0 |
| U-09 | 누락 검증 (DP10) | 빈 agents 디렉터리 / baseline 삭제 | strict 19 중 0, exit 1 / "시험 자산 없음" | P0 |
| F-01 | M1 CLI 일회 실행 | `aegis run d1-05 --input` | block D1-05.unicode-tag | P0 |
| F-02 | M1 REST 상주 서버 | `aegis serve d2-03 --port 8081` + POST /v1/judge | 200 transform, 마스킹 | P0 |
| F-03 | M1 MCP stdio 서버 | MCP 클라이언트 initialize·list_tools·call_tool | 도구 3종, judge block, explain 설명 | P0 |
| F-04 | 커버리지 게이트 실제 실행 | `scripts/verify_coverage.py` | 현재 엄격 2/19 → exit 1 (E5 전 기대 동작) | P0 |
| F-05 | 에이전트 목록 | `aegis list` | 3종, 계열·격리·failMode 표시 | P1 |
