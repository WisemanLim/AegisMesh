# 시험 결과 / Test Result — impl 21st (Epic 21 첫 실행 마법사 ②~⑤ + 설치 검증)
- 일자: 2026-10-06 · 대상: local compose(SQLite) + 헤드리스 Chromium(gstack browse) · 커밋: —

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 2회: 첫 판정 경과 음수, 첫 판정 화면 표시)
- `make test` **293 passed** · `make test-web` 7 + tsc · 마법사 4화면 + /install 콘솔 오류 0

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T21-01 | PASS | 설치 05:00:21Z(부트스트랩 기록) · 경과 116분 · 설치 후 첫 판정 4.9분(목표 30분 이내) · 단계 4/5 → 검증 후 5/5. 이관 데이터(설치 전 판정)는 제외 |
| T21-02 | PASS | input d1-05 · tool d3-01 · output d2-03 도달(0.2ms, 증적 seq 44244~44246) · 격리·서명·강등 기본값(C1·C2 closed / C3·C4 open)·누락 80/80 · 원장 `install_verified` |
| T21-03 | PASS | tenant_admin(default)·security_engineer → 403 (pytest) |
| T21-04 | PASS | 비로그인 `/setup/identity` → `/login?next=%2Fsetup%2Fidentity`, `/setup` 은 공개 유지 |
| T21-05 | PASS | 신뢰 도메인 spiffe://aegismesh.local · 수명 1시간·50% 회전 · SVID 유효 84(에이전트 80·플랫폼 4·서비스 1) · 정적 API 키 0 ✓ · OpenBao 선택 연동·Vault BUSL 안내 |
| T21-06 | PASS | “기본 테넌트 증적 보존 365일 — 원장 기록” → 90 복원 · 원문 보존 꺼짐 · 외부 모델 deny · 수집기 otel-collector:4318, memory_limiter → transform/mask → batch, 마스킹 6종 |
| T21-07 | PASS | chatbot-baseline + 출력 유출 표본 → transform(d2-03 aws-access-key, “값은 기록하지 않음”) 14종 중 8종 0.9ms/150ms · minimal-visibility + 지시 주입 → observe 단계 allow(C3·C4 만 선택 — “위험 없음” 표시) |
| T21-08 | PASS | “설치 검증 통과 — 관문 3/3 · 기동 검사 4/4 · 경고 0”, 사전 점검 8/8, 단계 표시 5/5 ✓ |
| T21-09 | PASS | 293 passed · vitest 7 · tsc · 브라우저 콘솔 오류 0 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 첫 판정까지 −117.8분 | 0006 이전(이관) gate 기록이 설치 시각보다 앞섬 | 설치 시각 이후 첫 gate 기록만 집계 + 시험 단언(≥0) | 4.9분 |
| 1 | 첫 판정 화면 “에이전트 d2-04종”, 근거 칸 비어 있음 | 액션 결과 펼침이 개수를 에이전트 ID 목록으로 덮어씀 · decisions.reasons 는 정책 사유만 | `agentCount` 분리, 근거는 Finding evidence.note | PASS |
| — | /setup 하위가 비로그인 접근 가능 | 미들웨어 공개 경로 접두 일치 | `/login`·`/setup`·`/logout` 정확 일치만 공개 | 리다이렉트 확인 |

## 설계 결정 기록
- 설치 시각 = min(부트스트랩 토큰 발급 기록, 기본 테넌트 생성). 첫 판정 = 그 이후 첫 `gate` 원장 기록. 설치 검증 자체 판정은 `setup` 종류라 첫 판정에 넣지 않음.
- 부트스트랩 완료 → `/setup/identity`(②)로 이어짐. 설치 검증은 플랫폼 관리자 전용(`tenant.admin`, PLATFORM_ONLY) — 설치 전체·platform 체인에 기록하므로.
- 보존 기간은 기존 PATCH /v1/tenants 재사용(원장 기록). 원문 보존·외부 모델 호출은 화면에서 바꾸지 않음(승인 필요, 원문 저장 기능 없음).

## 로그
- logs/make-test.txt · make-test-web.txt · local-all.txt · setup-status-before.json · e2e-routes.txt · e2e-a07-a08.txt · e2e-actions.txt
