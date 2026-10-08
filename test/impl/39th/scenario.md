# 시험 시나리오 / Test Scenario — impl 39th (Epic 39 접근성 AA 점검·수정)
- 근거: PRD.md §7 가정 "준수 목표 KWCAG 2.2 / WCAG 2.2 AA"(원본 UI p.19·p.153: 색 + 글자 병기, 키보드 포커스 2px 외곽선, KRDS 참고) · 계획표 39 수용 기준 "전 경로 axe 자동 점검 위반(serious·critical) 0, 키보드 포커스·대비·라벨·랜드마크".
- 방식: `make e2e-a11y` — Playwright Chromium + axe-core 4.10.3(태그 wcag2a·2aa·21a·21aa·22aa). 콘솔 경로 틀(apps/web/app/**/page.tsx 74개)을 ko·en 으로 연다. 동적 경로는 목록 화면 링크에서 실제 ID 를 찾는다(도메인 화면은 전부, 나머지 틀마다 1개). 로그인·2단계·등록·재인증 화면은 흐름 안에서 점검(등록·재인증은 수단 없는 승인자 시험 사용자를 만들어 쓰고 끝에 비활성화).
- 판정: axe serious·critical 노드 0 + 키보드(첫 Tab = 본문 바로가기, Enter → main 초점, Tab 30회 동안 초점 표시·초점 가림 없음) + 입력 목적(username·current-password·one-time-code).
- 환경: local compose(dev 서버) · plat.admin(OTP) · 시험 사용자 a11y.e2e*(approver, 실행마다 생성·비활성화)

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T39-01 | 기준선 측정 | 수정 전 전 경로 ko·en | 위반 규칙·노드 수 기록 | P0 |
| T39-02 | 글자 대비(1.4.3) | 판정·심각도 배지, 배너, 보조 글자, 위험 지도 칸 | color-contrast 0 | P0 |
| T39-03 | 색만으로 구분 금지(1.4.1) | 글 속 링크 | link-in-text-block 0 | P0 |
| T39-04 | 대상 크기(2.5.8) | 체크박스·라디오 | target-size 0 | P1 |
| T39-05 | 이름·라벨(4.1.2) | 선택 상자 | select-name 0 | P0 |
| T39-06 | 키보드 스크롤(2.1.1) | 넘치는 코드·표 영역 | scrollable-region-focusable 0 | P1 |
| T39-07 | 블록 건너뛰기(2.4.1) | 첫 Tab · Enter | 본문 바로가기 → main 초점 (ko·en 5화면) | P0 |
| T39-08 | 초점 표시·가림(2.4.7·2.4.11) | Tab 30회 × 5화면 × ko·en | 표시 없음 0 · 가림 0 | P0 |
| T39-09 | 입력 목적·인증(1.3.5·3.3.8) | 로그인·2단계·등록·재인증 | autocomplete username·current-password·one-time-code | P1 |
| T39-10 | 전 경로 회귀 | 74 틀 ko·en (깊은 도메인 경로 포함) | serious·critical 0 | P0 |
