# 시험 결과 / Test Result — impl 7th (Epic 7 2단계 에이전트 22종)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite) · 커밋: —

## 요약 / Summary
- 전체 11 (pytest 139건 포함), 통과 11, 실패 0 → 최종 **PASS** (재시도 3회)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-09 | PASS | `make test` 139 passed · `aegis eval --all` 42 PASS |
| U-02 | PASS | `coverage: 전체 42/80 · 엄격 31/31` |
| F-01 | PASS | regulated-kr 35종 바인딩(미구현 9: D1-04·D10 7·X08) · 출력 `block [D2-01.rrn]` · 도구 `require_approval [D3-01, D6-07]` + 승인 요청 생성 · offline `block [D2-06.secret-in-logs]` |
| F-02 | PASS | 입력 10종 p95 0.47ms / 도구 14종 p95 0.50ms / 출력 9종 p95 0.40ms, 예산 초과 0 (각 300회) |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | D2-07 오탐: 백업 유예 기간 내 잔존도 차단 | 유예 신호 점수 0.6 ≥ 판정 하한 | 유예는 정보 신호(0.3) | PASS |
| 1 | D2-01 미탐: 영문 "Patient: John … HIV" | 이름 문맥이 한글만 | 영문 라벨 문맥 추가 | PASS |
| 1 | D2-04 대리 실행 검사 무효 | 역할 집합 연산이 항등식 | 사람·대리 에이전트 각각 ACL 검사 | PASS |
| 2 | D4-01 오탐: 문장 끝 마침표가 숫자에 붙음 / 미탐: "25" 가 "1,250" 부분 문자열로 통과 | 수치 대조를 부분 문자열로 함 | 수치 토큰 집합 대조 | PASS |
| 2 | D4-02 오탐 `arXiv:…v2` / 미탐 `doi:10.12/abc` | 판번호·접두 DOI 파싱 | 판번호 제거, `doi:` 접두 후보 별도 검증 | PASS |
| 2 | D4-03 오탐 `lookup_order` / 미탐 `approve_loan` | 행동 이름 부분 문자열 매칭 | 토큰 단위 + 조회 동사 제외 | PASS |
| 3 | 기존 시험 3건 실패 | 시험이 "d4-01 미구현"·"엄격 19" 전제 | 내장 항목 일시 해제 fixture, 단계 명시 | PASS |
| — | 계획 누락: 1단계 P1 D1-04·D5-05·D5-07 이 어떤 Epic 에도 없음 | 1차 계획이 P0 만 다룸 | Epic 9 에 편입 | 계획 갱신 |

## 한계
- 시험 데이터는 에이전트당 10건 자체 코퍼스 — 과적합 위험. X01 은 실제 Ed25519 서명 검증(키는 시험 생성).
- D4-01 근거성은 어휘·수치 대조 규칙 — 의미 수준 근거성(NLI 분류기)은 엔진 교체 대상(DP8).

## 첨부 / Logs
- logs/make-test.txt, coverage.txt, eval-all.txt, f-gates.txt
