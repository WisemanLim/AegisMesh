# 시험 결과 / Test Result — impl 39th (Epic 39 접근성 AA 점검·수정)
- 일자: 2026-10-07 · 대상: local compose(dev 서버) + Playwright Chromium + axe-core 4.10.3 · 커밋: —

## 요약 / Summary
- 전체 10, 통과 10, 실패 0 → 최종 **PASS** (재시도 4회: 경로 시간 초과 / 콘솔 세션 끊김(실결함) / ONLY 목록 소모 / 도메인 깊은 경로 누락)
- 최종: 전 경로 162쪽(run-r3) + 도메인 깊은 경로 114쪽(run-r5) — **위반 0건(모든 영향도)** · 키보드·입력 목적 38/38 · `make test-web` 14 + tsc
- 기준선(run-r1, 159쪽): color-contrast 2,671 · link-in-text-block 306 · target-size 271 · scrollable-region-focusable 10 · select-name 2(critical) · 본문 바로가기 0/10
- 측정으로 찾은 결함: 판정·심각도 색(승인 요구 2.62:1, 허용 3.49:1, 정보 3.06:1)이 글자·흰 글자 바탕으로 쓰여 AA 미달, 글 속 링크가 색으로만 구분, 체크박스 13px, 키보드 사용자의 블록 건너뛰기 수단 없음. 그리고 **dev 서버가 메모리 임계로 자동 재시작하면 콘솔 세션이 모두 끊김**(봉인 키가 `.next/` 에 있어 재시작 때 지워짐)

## 구현
- 디자인 토큰 — 같은 색상(hue)에서 명도만 낮춤: allow #187b43 · block #cd2d2d · approval·sev-medium #9d5d08 · transform·sev-low #2366db · sev-info #626d81 · muted #636c81 (흰 바탕·#f5f6fa·primary-soft 위 4.6:1 이상). 배너 info #257a6e · warn #9d6105. 위험 지도 '부분 차단'·'경보 전용'은 연한 바탕 + 진한 글자
- `globals.css` 본문 바로가기 · 글 속 링크 밑줄 · 체크·라디오 18px + 여백(24px 간격) · Shell `<a href="#main">` + `<main id="main" tabIndex=-1>`
- 넘치는 코드 블록·표 영역 `tabIndex=0`(15곳) · 시나리오 선택 상자 이름 · 판정 배지 보조 글자 불투명 · OTP 입력 `autocomplete="one-time-code"`·`inputMode=numeric`(등록·재인증·계정)
- `apps/web/lib/dpop.ts` 봉인 키 대체 위치 `.next/cache/aegis-web-secret` (dev 재시작에도 유지)
- 점검 도구: `infra/e2e/Dockerfile` axe-core 4.10.3(npm 공식 배포본, 판 고정) · `test/e2e/a11y_e2e.py` · `make e2e-a11y [ONLY=]` · compose e2e 에 경로 목록 읽기 전용 마운트

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T39-01 | PASS | 기준선 위 수치(run-r1 · logs/run-r1.txt) |
| T39-02 | PASS | color-contrast 2,671 → 0 |
| T39-03 | PASS | link-in-text-block 306 → 0 |
| T39-04 | PASS | target-size 271 → 0 |
| T39-05 | PASS | select-name 2 → 0 (`/redteam/run` 시나리오) |
| T39-06 | PASS | scrollable-region-focusable 10 → 0 (설치·실행 안내 코드, d5 신원 표 등) |
| T39-07 | PASS | ko·en × overview·incidents·catalog·approvals·policies 첫 Tab = 본문 바로가기, Enter → main |
| T39-08 | PASS | 30 정지점 × 10 — 초점 표시 누락 0 · 가림 0 |
| T39-09 | PASS | 로그인 username·current-password, 2단계·등록·재인증 one-time-code |
| T39-10 | PASS | 74 틀 전부 ko·en (깊은 도메인 경로 calls·grounding·lineage·inspect 포함) — 위반 0 |

## 회차 / Rounds
- round 1: `/domains/D1` 첫 컴파일 30초 초과 → 이동 시간 90초 + `load` 뒤 짧은 대기(주기 갱신 화면은 networkidle 이 오지 않는다) + 시간 초과 1회 재시도
- round 2: 기준선 측정 뒤 수정 → 일부 경로 재시험 중 `session lost` — 원인: Next dev 서버가 메모리 임계로 자동 재시작하며 `.next/` 를 비워 봉인 키(`.next/aegis-web-secret`)가 새로 생기고 모든 콘솔 세션 쿠키를 못 엶 → 키를 `.next/cache/` 로 이동(실결함 수정)
- round 3: `ONLY` 목록을 큐로 그대로 써 pop 으로 비워져 en 회차가 전 경로를 돌았다 → 복사본 사용, ONLY = 시작 경로(동적 링크는 계속 따라감)
- round 4: 전 경로 PASS(162쪽) 뒤 도메인 깊은 경로 4틀 미도달 → 도메인 화면 한도 확대 · 시작 경로로 재점검 → d5 신원 표 스크롤 영역 1건 추가 발견·수정 → PASS(114쪽)

## 남은 것 / Notes
- 자동 점검은 WCAG 일부만 판정한다(axe 는 대략 30~40%). 화면 낭독기 실제 사용·확대 400% 재배치(1.4.10)·움직임 등은 수동 점검 대상 — 이번 차수 범위 밖.
- 시험 사용자 a11y.e2e* 는 실행마다 비활성화(중간 중단된 2회분도 비활성 처리 — 보고 참조).
