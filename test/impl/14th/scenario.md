# 14차 시나리오 — Epic 14 관문·정책 관리

근거: FR-P02(정책 결정점), FR-P04·P15(오케스트레이션·강등), SCR-D01 관문 구성, SCR-D02 지연 예산, SCR-D03 정책 목록·버전,
SCR-D04 편집기·단위 시험·배포, SCR-D05 시뮬레이터, SCR-D06 강등 현황, SCR-C08 프로파일 편집기.

| id | 목적 | 입력 | 기대 | 우선 |
|---|---|---|---|---|
| T14-01 | 정책 목록·버전·diff | `/policies`, `GET /v1/policies/{id}/versions·diff` | 버전 이력, unified diff | P0 |
| T14-02 | 단위 시험이 배포를 막는다 | 기대가 틀린 tests 로 배포 | 422 unit-test, 버전 그대로 / 고친 뒤 배포 → 새 버전 | P0 |
| T14-03 | 시험 실행은 저장 없음 | `POST /v1/policies:test` | 결과 + diff, 버전 그대로 | P1 |
| T14-04 | 시뮬레이터 무영향 | `/simulate` 초안 재정의(D3-01→alert) | 배포 require_approval vs 초안 alert, 변경 영향, 판정·원장·승인 수 불변 | P0 |
| T14-05 | 시뮬레이션 = 실제 판정 | 같은 요청을 `judge:batch` | 시뮬레이터 배포 판정과 같은 verdict | P0 |
| T14-06 | 롤백은 2인 승인 | garam 정책 롤백 요청 → 승인 2명 | 승인 전 그대로, 요청자 본인 403, 2/2 후 새 버전 = 대상 본문, action_applied 원장 | P0 |
| T14-07 | 관문 구성·강등 현황 | `/gates` | 관문별 예산·하드 타임아웃·바인딩·failMode·p95·강등 기록 | P1 |
| T14-08 | 프로파일 편집기 | `/profiles/edit` 검증·저장 → `/instant` 적용 | 오류 표시·경고·관문 예산·승인 필요 항목, `<tenant>.<id>` 저장, 다른 테넌트 비공개 | P1 |
| T14-09 | 회귀 | `make test`, `make test-web`, coverage | 전부 통과 | P0 |
