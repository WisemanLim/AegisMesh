# 시험 결과 / Test Result — impl 36th (Epic 36 실제 트래픽 미리보기 — 마스킹 표본)
- 일자: 2026-10-07 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 1회: 시험 요청의 auth.method 값이 스키마 밖)
- `test_samples` 1 passed · 화면 E2E(logs/e2e.txt) · 콘솔 오류 0

## 구현
- 0015: `tenants.sample_retention`, `traffic_samples`(RLS) · `app/samples.py`(설정·2인 승인 행동·마스킹 수집·목록·라벨·축소·만료·미리보기 표본) · 판정 경로 수집(같은 커밋, 스트림 청크 제외) · 미리보기 `source=traffic`·`target`, 결과 `traffic` 요약·항목 `original` · worker 만료·초과 삭제
- API `GET/PUT /v1/traffic-samples/settings`(PUT = privacy, 켜기·확대 2인) · `GET /v1/traffic-samples`(quality) · `PUT /v1/traffic-samples/{id}/label` · `DELETE /v1/traffic-samples`
- 콘솔: 미리보기 표본 선택(시험 코퍼스 / 실제 트래픽·마스킹 N건, 꺼져 있으면 비활성·안내), 실트래픽 요약·원래 판정 열·라벨 버튼 · 데이터 보호 '미리보기 표본 보존' 카드(상태·폼·마스킹 표본 표·전부 삭제)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T36-01 | PASS | 표본 0 · 409 “실제 트래픽 표본 없음” |
| T36-02 | PASS | developer 403 · maxSamples 5 → 422 · pending → 2인 → {enabled, 50, 7} · 화면: 요청 apr_5ddd3a09e7f5 → appr.one pending → appr.two approved |
| T36-03 | PASS | 원값 4종 부재 · masked rrn·email·api_key · p:해시 · auth 없음 · 화면: “[REDACTED_RRN]·[REDACTED_EMAIL]·[REDACTED_CARD]” |
| T36-04 | PASS | pytest: 총 ≥3·라벨 ≥1·차단 예상 ≥1·정상 ≥1 · 화면: 실제 트래픽 5 · 차단 예상 1 → 정상 라벨 1 → “오탐 추정 0.0% (정상 1)” |
| T36-05 | PASS | 축소 applied · 만료 1+ 삭제 · 끄기 = 0건, 이후 판정 미수집 · 화면 “보존 끔 · 삭제 5건” |
| T36-06 | PASS | en 미리보기 한글 0 · 데이터 보호는 마스킹된 표본 본문(사용자 데이터)만 한글 · 콘솔 오류 0 |

## 남은 것 / Notes
- 표본은 마스킹 규칙(관측과 공용 6종) 밖의 개인정보(이름·주소 자유 서술)는 가리지 못한다 — 켜기 승인 시 확인 사항으로 화면에 규칙을 표시한다. auth·session 을 지우므로 D5 계열 일부는 재생에서 신호가 약하다.
