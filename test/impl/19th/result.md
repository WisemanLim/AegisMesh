# 시험 결과 / Test Result — impl 19th (Epic 19 콘솔 잔여 화면 + 브라우저 E2E)
- 일자: 2026-10-06 · 대상: local (SQLite, dev) + prod 리허설 (PostgreSQL 17, web standalone) · 커밋: —
- 브라우저: 헤드리스 Chromium (gstack browse) — plat.admin · eng.kim · plat.appr1/2 실제 로그인

## 요약 / Summary
- 전체 10, 통과 10, 실패 0 → 최종 **PASS** (재시도 1회: X 페이지 시험 표본 형태)
- `make test` **290 passed** (+ test_console 6) · `make test-web` 7 + tsc · coverage 80/80 · ruff(F,E9) clean
- 전 화면 스윕 **45/45** (local·prod) — 오류 화면 0 · 로그인 튕김 0 · 콘솔 오류 0

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T19-01 | PASS | ⌘K → “d1-05” → 에이전트·도식 항목·사건, Enter → /catalog/d1-05 · “증적” → 화면 · “>” 명령 9종. 테넌트 엔지니어는 플랫폼 명령 5종 비활성 + “권한 없음: redteam…” |
| T19-02 | PASS | 🔔 9 → /notifications: 승인 대기·사건·승인 실행(market_install)·서명·반입 실패(hash) 시간순, 항목 → 해당 화면 |
| T19-03 | PASS | tool-agent·enforce 재생 256 표본: allow 107 · alert 5 · transform 20 · require_approval 29 · block 95, 미탐 추정 0%, 관문 p95 입력 4.9/80·도구 0.59/20·출력 0.42/150ms, 에이전트 기여. (판정, 원장, 승인) 수 불변 |
| T19-04 | PASS | /catalog/d2-03/run: CLI·REST·MCP 스니펫, A2A AgentCard(skills·SVID), 지금 시험 → transform `[REDACTED_AWS_ACCESS_KEY]` + 근거 |
| T19-05 | PASS | X01 block unsigned-card · X04 block unregistered · X05 transform xss · X06 block embedded-instruction · X07 block open-endpoint(+L3 전용 안내). x04 강제 종료 → 격리 qtn_… · 토큰 회수 1 → 탈취 토큰 200→401 · 관문 block(PLATFORM.quarantine) |
| T19-06 | PASS | 대상 d1-05·d2-03·d3-01 → 승인 요청 → 1/2 → 2/2 → 캠페인 실행(by approval:apr_…, 3종, 회귀 0, ko/en 공정성) |
| T19-07 | PASS | 기준선 “배포 게이트 통과 — 회귀 0 · 엄격 누락 0”, 커버리지 80/80·43/43 · 데이터 보호 5 영역 · 토폴로지 T2 노드 6 모두 ok |
| T19-08 | PASS | lang=en → Human approval inbox · Policies · versions · Telemetry pipeline… · Sandbox · isolation pools · Marketplace · Deployment topology, 메뉴 그룹 영어 |
| T19-09 | PASS | 45 경로(동적 포함) local 45/45 · prod 45/45 |
| T19-10 | PASS | 290 passed · vitest 7 · tsc · coverage · ruff |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | X06·X07 시험 콘솔이 allow | 페이지 기본 표본이 에이전트가 읽는 형태(params.attachments·inference_server)와 다름 | 각 에이전트 공격 코퍼스 형태로 교체 | round 2 X01·X04·X06·X07 block |
| — | 스윕 첫 실행 45/45 BAD | 시험 도구: zsh 단어 분리 안 함 → 경로 전체를 한 URL 로 요청, 브라우저 콘솔 버퍼가 세션 전체 누적 | bash 스크립트 + 경로마다 `console --clear` | 45/45 |
| — | 기준선 화면 누락 정보 미표시 | 커버리지 응답 필드명 가정(strict.missing) | 실제 `strict.failures` 사용 | 확인 |

## 관찰 (결함 아님)
- 미리보기의 오탐 추정 16.4% 는 각 에이전트의 정상 코퍼스를 같은 관문의 **다른 에이전트**까지 통과시킨 결과(교차 오탐) — 프로파일 조합 오탐 신호로 그대로 보여 준다. 에이전트 단독 오탐은 R5·레드팀에서 0.

## 설계 결정 기록
- 원문 미보존(NFR-D1) 때문에 “최근 트래픽 재생”은 붙여 넣은 표본 또는 바인딩 에이전트의 시험 코퍼스로 대신한다.
- 명령 팔레트의 명령은 해당 화면으로 이동만 — 파괴적 작업은 화면의 확인·승인 절차를 그대로 거친다.
- NFR-C4: 셸·메뉴·모든 화면 제목은 한·영. 화면 본문 문구 일부는 한국어 그대로(후속).

## 첨부 / Logs
- logs/ (비커밋): t19-*.txt, sweep local·prod, 스크린샷 6장
