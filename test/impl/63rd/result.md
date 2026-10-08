# 시험 결과 / Test Result — impl 63rd (Epic 63 보조기술 점검 자동화)
- 일자: 2026-10-08 · 대상: local 콘솔, Playwright 1.55 Chromium 접근성 트리 + axe 4.10 · 커밋: —

## 요약 / Summary
- 전체 5, 통과 5, 실패 0 → 최종 **PASS** (재시도 2회: 셸 밖 화면 예외 / dev 서버 재시작 중 키보드 단계 이동 시간 초과)
- `make e2e-a11y` 에 쪽마다 보조기술 점검 4종(랜드마크·제목 구조·접근 가능한 이름·쪽 제목+lang) — 일부 경로 실행 136쪽 **4종 × ko·en 전부 통과**, serious·critical 0, 키보드·인증 56/56 (전 경로는 10차 게이트 전수 점검)
- 상태 알림: 클라이언트 컴포넌트 13개·22곳의 동적 오류 문구에 `role="alert"` 가 없었다(낭독기가 알리지 않음) → 부여 + 재발 방지 vitest(`a11y-live.test.ts`)
- 함께 고친 것: `/domains/d4/decisions` 판정 목록 링크 대상 크기(데이터가 늘며 target-size serious) → 24px

## 구현
- `test/e2e/a11y_e2e.py` — `assistive()`(DOM 랜드마크·제목 단계·쪽 제목·lang + `aria_snapshot` 의 이름 없는 컨트롤), 셸 밖 화면 예외, 게이트 4종(ko·en), 공통 `goto` 재시도(dev 서버 메모리 임계 재시작)
- `apps/web/components/*` 동적 오류 `role="alert"` · `apps/web/test/a11y-live.test.ts` · `apps/web/app/domains/_screens/d4.tsx` 링크 `min-h-6`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | probe3 `[ko] AT landmarks 69/69` · `[en] 67/67` |
| C02 | PASS | probe3 `AT headings 69/69` · `67/67` |
| C03 | PASS | probe3 `AT accessible names 69/69` · `67/67` |
| C04 | PASS | probe3 `AT page title + lang 69/69` · `67/67` |
| C05 | PASS | `make test-web` 18 passed(a11y-live 포함) |

## 회차 / Rounds
- round 1: 로그인·2단계·등록·재인증 쪽이 banner·nav 없음으로 걸림 — 셸 밖 화면(설계상 단독 화면)이라 main 만 요구
- round 2: 키보드 단계의 쪽 이동이 dev 서버 메모리 임계 재시작 중 90 s 시간 초과 — 크롤 단계와 같은 1회 재시도로

## 남은 것 / Notes
- 실제 화면 낭독기(NVDA·JAWS·VoiceOver)로 듣는 사용성 점검은 여전히 사람 몫 — 이 점검은 낭독기가 받는 구조가 맞는지까지.
