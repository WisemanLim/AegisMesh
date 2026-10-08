# 시험 결과 / Test Result — impl 32nd (Epic 32 작업 흐름 화면)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 4회: 저장 판정 재파싱 실패 / 비교 경로 가림 / 만료 거절 롤백 / 전체 차단 단계 누락 안내)
- `make test` **366 passed** (+ test_workflow 5) · `make test-web` 14 + tsc 0 · 콘솔 오류 0
- 측정으로 찾은 결함: **저장 판정 재파싱 실패**(무해화 결과 `action.transformApplied` 가 스키마 밖 → 재평가 0건) → 재파싱 시 제거 · **`/profiles/{id}:compare` 가 GET `/profiles/{id}` 에 가려짐** → `/profiles/{id}/compare` · **만료 승인 결정의 자동 거절이 409 와 함께 롤백** → 거절 커밋 후 409 · **자체 SBOM 이 두 벌**(airgap 무서명·신규 서명) → airgap SBOM 에 서명만 덧붙임

## 구현
- 백엔드: `protected_targets`(0013, RLS) · `approvals.expires_at` + `APPROVAL_TTL_MIN`(worker `expire_due`) · `app/instant.py`(보호 대상·비교·부분 차단 파생 프로파일·단계 적용·해제·승인 행동 `profile_apply`·`target_external_model`) · `app/workflow.py`(승인 문맥·트레이, 런북 5단계·`runbook_step` 승인 행동, 재평가·포렌식 보존·재현, 업데이트·롤링 교체·서명 SBOM)
- 콘솔: `/instant/{profiles,targets,preview,apply}`(CMP-12 stepper, 선택값 p·t 쿼리 전달, 다음 비활성 조건) · `/approvals/[id]`(O06) · Shell 트레이 드로어 `components/Tray.tsx`(B07, 열 때 불러옴·카드 빠른 결정) · `/incidents/[id]/response`(O07) · `/admin/updates`(+ `sbom` 내려받기) · `components/ConfirmButton`(MSG-018·019)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T32-01 | PASS | pytest: 422·observe·비교(regulated-kr: 외부 모델 deny·보존 1825일)·부분 `…-p-d1-d3`(D1·D3 외 alert)·전체 = 승인 1 → 적용·해제 → 직전 부분 복귀·적용 중 삭제 409 · 화면: 형식 오류 MSG-004, 저장·연결 시험(allow 0.26ms, 미적용 = 기본 탐지기), 부분 적용 → 파생 프로파일, 관측 → 부분 → 해제 = “이전 스냅샷 minimal-visibility(observe) 으로 복귀” |
| T32-02 | PASS | regulated-kr 대상 외부 모델 → externalModel false + 승인 요청 → 2인 승인 → true |
| T32-03 | PASS | 문맥 금액 2,400,000·되돌릴 수 없음·지출·A4·주체, 트레이 카드, TTL 0 → 409 “만료” + status expired |
| T32-04 | PASS | 격리·봉쇄·회전(승인 → 신원 회전·임대 회수)·재평가 1·보존 다이제스트 64자·재현 1/1·핫픽스 409 → 정책 배포 후 200·해제·사후·종결, 단계 전부 완료·법적 보존 |
| T32-05 | PASS | 에이전트 80·교체 ok(1.0.0→1.0.0)·developer 403·CycloneDX + Ed25519 서명 JWKS 검증 · 화면: d1-01 교체 완료·이력·내려받기 JSON(CycloneDX 142·EdDSA) |
| T32-06 | PASS | logs/e2e.txt·e2e-r2.txt · c04~c07·b07·o06(b)·o07·r05-ko.png — 비교(+14·D1 +7·지연·격리 L0 ✓), 오탐 5.4% > 0.5% → 전체 차단 비활성·단계 미선택 MSG-003, 확인 대화상자 수락 기록, 트레이 빠른 승인(사유 필수·1/2)·빈 사유 거절 막힘·거절 → rejected, 본인 요청 승인 비활성·이미 결정 차단, 지출 막대 24%·보상 “환수 요청 런북 RB-11”, 런북 단계·보존·재현 표 |
| T32-07 | PASS | en 10 경로 + 트레이: 화면 문구 한글 0 — 남은 것 = 저장 데이터(사유·런북 본문·원장 상세·이전 파생 프로파일 문구), 366 passed · vitest 14 · tsc 0 |

## 회차 / Rounds
- round 1: 재평가 total 0 → 저장 판정 본문의 `action.transformApplied`(무해화 표시)가 Finding 스키마 extra=forbid 에 걸림 → `_finding` 이 제거 후 검증
- round 2: 비교 404 → `:compare` 가 GET `/profiles/{pid}` 경로에 먼저 잡힘 → `/compare` 하위 경로 · 만료 결정 409 뒤 상태가 pending 으로 남음 → 자동 거절을 커밋한 뒤 409
- round 3: 화면 E2E 에서 전체 차단 제출 → 원시 422(stage null) — 오탐 추정 5.4% 로 전체 차단 라디오가 비활성(설계대로)이라 값이 안 실림 → 액션이 단계 누락을 MSG-003 으로 안내
- round 4: 영어 모드 — 비교 `approvalNeeded`·부분 차단 `blocking`·재현 격리 문구·승인 요약이 서버 한국어 → 코드/중립 문구로 바꾸고 화면이 언어별 표시

## 남은 것 / Notes
- 전체 차단은 미리보기 오탐 추정 0.5% 이하에서만 켜진다 — 기본 코퍼스로는 대부분 프로파일이 넘어서 화면에서는 부분 차단까지가 일반 경로(API 는 승인 대기 경로 시험 완료).
- L3 재현 런타임이 없어 재현은 L0(프로세스 안) — 결과에 그대로 표시. 외부 대응 도구(TheHive·MISP·Wazuh)는 알림 채널·SIEM 내보내기로만 연동.
