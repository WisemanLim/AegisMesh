# 시험 결과 / Test Result — impl 33rd (Epic 33 공정성·시스템 카드, P2)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 2회: 차단율만 있는 측정을 '미측정'으로 오판 / 카드 데이터 줄 버전 없는 항목 '—' 표시)
- `make test` **369 passed** (+ test_compliance 3) · `make test-web` 14 + tsc 0 · d10-05 1.1.0 골든 15·공격 14 오탐 0·탐지 1.0 · 콘솔 오류 0
- 측정으로 찾은 결함: **D10-05 가 집단별 차단율을 보지 않음**(코퍼스 오탐·탐지 격차만) → `block-rate-gap`(축별 %p 한도 `maxGapPp`) 추가 · **D10-06 이 언제나 통과**(카드 = 에이전트 매니페스트 사본, 변경 시각 없음) → 보호 대상·모델 카드의 입력 지문으로 changedAt · **판정 기록에 보호 대상이 없음** → `target` 기록(대상별 집계)

## 구현
- 요청 `subject.groups`(가명 범주 라벨 — 키 `[a-z][a-z0-9_]{0,15}`·값 24자 범주·8축 이하) + 판정 기록 모양에 `groups`·`script`(문자 체계, lang 축 기본값) · 판정 기록 `target`
- `app/compliance.py`: 집단별 차단율·격차, 레드팀 코퍼스 성능 분해, 측정(d10-05 → 원장 `fairness`, 한도 초과 = 위험 등록부·같은 출처 재사용), 영향 평가(원장 `impact_assessment`, 없음·180일·이후 초과 = 갱신 필요), 공개 설정(원장 `disclosure`), 카드 생성(ko·en 7 섹션, 지문 = 목적·모델·데이터셋·프로파일·정책)·목록(최신·초안·검토 중·갱신 필요·없음)·문서(Markdown)·공개 요청(승인 행동 `card_publish`)·배포 게이트(회귀 + 카드)·거버넌스 스냅샷 카드
- API `/v1/compliance/{fairness,fairness:measure,fairness/assessments,fairness/disclosure,cards,cards:generate,cards/{s}/doc,cards/{s}:publish,deploy-gate}` · 권한 `compliance.write`(플랫폼 관리자·규제 대응) · worker 주 1회 정례 측정 `FAIRNESS_INTERVAL_SEC`
- 콘솔: `/compliance/fairness`(N06) · `/compliance/cards`(+ `doc` 내려받기, N07) · 기준선 화면 배포 차단 사유에 카드

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T33-01 | PASS | 이메일 값·대문자 키·9축 → 422 |
| T33-02 | PASS | pytest: ko 0% · foreign 25% → lang 격차 > 1.5%p, age 단일 집단 비교 제외, developer 403, 측정 alert `D10-05.block-rate-gap` + 위험, 재측정 같은 위험 · 화면: 판정 100건 → lang 20.00%p 한도 초과(적색·“초과”), channel web n=20 비교 제외, 위험 R-978e85 등록 |
| T33-03 | PASS | 없음 → 기록 후 승인 → 재측정 초과 후 갱신 필요 · 화면: 평가 기록·외부 공개 토글 저장 |
| T33-04 | PASS | 없음(게이트 차단) → v1 초안 → 같은 지문 새 판 없음 → 검토 중 → 승인 → 최신(internal·regulator) → 공급자·데이터셋 변경 = 갱신 필요(model.provider·data.* 변경 목록, 게이트 차단, 공개 409, 스냅샷 changedAt) → v2 changed {model, data}, 문서 en/ko |
| T33-05 | PASS | run5 골든 5(한도 안·소표본·단일 집단·차단율만·한도 완화)·공격 4(언어·연령·채널 엄격 한도·지역) — 오탐 0·탐지 1.0 |
| T33-06 | PASS | logs/e2e.txt·e2e-r2.txt · n06·n07·n07b·q03-ko.png — 카드 없음 → 자동 생성 2건 → 검토 요청 → 승인 후 최신 → 프로파일 전환 = 갱신 필요(controls.* 변경·공개 비활성) → v2(안전 통제 변경 강조), 기준선 “카드 갱신 필요 e2e-support-bot (MSG-021)”, 문서 en 내려받기 |
| T33-07 | PASS | en 4 경로 화면 문구 한글 0(남은 것 = 사용자가 입력한 평가 요약), 369 passed · vitest 14 · tsc 0 |

## 회차 / Rounds
- round 1: d10-05 골든 “차단율만(한도 안)” 이 `not-measured` 경보 → 차단율 축이 비교 가능하면 측정된 것으로
- round 2: 카드 데이터 줄 “upload-api —” (버전 없는 색인 갱신 대상) → 버전 없으면 이름만

## 남은 것 / Notes
- 집단 라벨은 게이트웨이(호출자)가 가명 범주로 실어 보낸다 — 플랫폼은 원문에서 속성을 추정하지 않는다(문자 체계만 기본 축). 실제 이용자 집단 오탐·미탐은 라벨이 필요해 코퍼스 캠페인 기준으로 분해했다.
- 이의 신청 재판정 결과의 골든셋 편입은 기존 판정 이의·라벨(SCR-O02) 흐름을 안내만 한다. 모델 카드의 학습 데이터 출처는 공급자 문서 몫.
