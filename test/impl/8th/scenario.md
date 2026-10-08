# 시험 시나리오 — impl 8th · Epic 8 상시 점검 실행 (C3)

근거: PRD §8.2 "상시 계열 D2·D7·D9 는 경로 밖에서 주기·이벤트로 돈다 … D7 이 특정 MCP 서버의 서명 위반을 발견하면 도구 관문의 허용목록에서 즉시 제외", §11.1, FR-D7-01, NFR-A4.
결정: compose `worker` 서비스 주기 점검 + `POST /v1/scan` (2차 실행 확인 답변). 시연을 위해 D7-01 을 앞당김.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| U-01 | offline 관문 에이전트 목록 | 레지스트리 | d2-06·d2-07·d7-01 포함 | P0 |
| U-02 | 즉시 점검 입력 검증 | kind 없는 artifact | 422 | P1 |
| U-03 | 정상 MCP 서버 | 서명·승인·고정 버전 | allow, 격리 없음 | P0 |
| U-04 | 위험 MCP 서버 → 격리 | 미서명·미승인·도구 설명 오염 | block + 격리 1건(재점검 시 중복 없음) | P0 |
| U-05 | 도구 관문 동적 차단 | `mcp__free-tools__run`, `server=free-tools` | PLATFORM.quarantine block, 다른 도구는 allow | P0 |
| U-06 | 격리 해제 | 익명 / 주체 지정 | 401 / 해제 + 증적(quarantined→released) + 관문 복귀 | P0 |
| U-07 | 점검 대상 + worker tick | 등록 → tick → tick | 첫 tick 실행(alert), 주기 전 재실행 없음, 수동 실행 | P0 |
| F-01 | worker 서비스 실기동 | local compose | api healthy 후 worker running, 재시작 0 | P0 |
| F-02 | 주기 점검 → 격리 → 관문 | 위험 서버 대상 등록(10초) | worker 실행 전 allow → 실행 후 block + 격리 | P0 |
| F-03 | 주기 반복 | 30초 대기 | 두 번째 점검, 같은 격리 재사용 | P1 |
