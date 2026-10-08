# 시험 결과 / Test Result — impl 5th (Epic 5 1단계 P0 에이전트 19종)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite) · 커밋: —

## 요약 / Summary
- 전체 9 (pytest 89건 포함), 통과 9, 실패 0 → 최종 **PASS** (재시도 3회 — 규칙 오탐·미탐 조정)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-07 | PASS | `make test` 89 passed |
| F-01 | PASS | 20종 전부 PASS — 오탐 0.000, 탐지 1.000, p95 ≤ 0.03ms (logs/eval-all.txt) |
| F-02 | PASS | 입력 9종 p95 0.44ms / 도구 7종 p95 0.29ms / 출력 4종 p95 0.21ms, 예산 초과 0건 (각 300회) |
| 커버리지 | PASS | `coverage: 전체 20/80 · 엄격 19/19` exit 0 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | D1-02 오탐: 목표 "send report" + 계획 "email" | 위험 동사를 단어 단위로 비교 | 행동군(전송·금전·파괴) 단위 비교 | PASS |
| 1 | D1-03 오탐: "without filters"(커피), "developer mode on Android" | 패턴 과포괄 | 대상 한정어(any/your/all)·활성화 표현 요구 | PASS |
| 1 | D1-03 미탐: GCG 적대 접미사 | 구두점 밀도 휴리스틱 약함 | 이상 토큰(\\, **, ](, !--, 붙여쓰기) 10토큰 창 3개 이상 | PASS |
| 1 | D1-06 미탐: hex 인코딩 파라미터 | hex 는 최대 엔트로피 4비트 → 3.5 기준 미달 | 긴 hex·base64 형태는 2.5 기준 | PASS |
| 2 | D3-04 오탐: `.env.example` | 민감 파일 패턴 과포괄 | example·sample·template·dist 제외 | PASS |
| 2 | D3-06 미탐: `*:*` 정책 | `\b` 가 `*` 앞에서 불성립 | 별도 대안 `^\*(:\*)?$` | PASS |
| 2 | D3-07 오탐: `execute_trade_report` | 코드 실행 도구 이름 과포괄 | 이름 패턴 정밀화 | PASS |
| 3 | 승인 후 재호출이 다시 require_approval | D3-05 가 송금 `amount` 를 대량 파라미터로 오인 + approved 무시 | amount 제외(D6-07 영역), approved 면 대량·컬렉션 승인 요구 생략 | PASS |
| 3 | E3 시험 실패 3건 | 시험이 "입력 관문 = d1-05 하나" 전제 | 에이전트 ID 로 판정 조회 | PASS |

## 한계 (정직한 평가)
- 골든셋·공격셋은 에이전트당 10~12건이고 규칙 작성과 함께 만들어 **과적합 위험**이 있다. 탐지율 1.000 은 자체 코퍼스 기준이다.
- NFR-Q2(공개 코퍼스 미탐 ≤10%: garak·JailbreakBench·HarmBench)는 아직 실행하지 않음 — 외부 엔진 어댑터(DP8)와 함께 후속.
- NFR-Q1 골든셋 1만 건 주간 재생은 실트래픽 표본 축적 후.
- 지연은 규칙 엔진 기준. 분류기 엔진을 붙이면 재측정 필요.

## 첨부 / Logs
- logs/make-test.txt, coverage.txt, eval-all.txt, local-all.txt, f-gates-latency.txt
