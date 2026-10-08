# 63rd — 보조기술 점검 자동화 (Epic 63 · 9차 한계 '화면 낭독기 등 보조기술 실사용 점검')

근거: 39th·45th 는 axe 규칙·키보드·재배치까지 — 화면 낭독기가 실제로 쓰는 접근성 트리(랜드마크·제목 구조·컨트롤 이름·상태 알림)는 따로 보지 않았다.
실제 낭독기(NVDA·VoiceOver) 사용은 자동화 대상이 아니므로, Chromium 접근성 트리(Playwright aria_snapshot)와 DOM 구조로 대신 점검한다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 랜드마크 | 전 경로 ko·en | main 정확히 1, 셸 화면은 banner·navigation 도(로그인·2단계·등록·재인증은 셸 밖 = main 만) | P0 |
| C02 | 제목 구조 | 〃 | h1 정확히 1, 제목 단계 건너뜀 없음 | P0 |
| C03 | 접근 가능한 이름 | 〃(접근성 트리) | 이름 없는 button·textbox·combobox·checkbox·radio·link·tab·switch 0 | P0 |
| C04 | 쪽 제목·언어 | 〃 | document.title 있음, `<html lang>` = 화면 언어 | P0 |
| C05 | 상태 알림 | 클라이언트 컴포넌트 정적 시험 | 사용자 동작 뒤 제자리 오류 문구 = role=alert(WCAG 4.1.3), Banner = status/alert | P0 |
