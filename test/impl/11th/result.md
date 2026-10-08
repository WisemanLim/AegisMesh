# 시험 결과 / Test Result — impl 11th (Epic 11 거버넌스·보고서·사건·레드팀)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite, api + worker + web) · 커밋: —

## 요약 / Summary
- 전체 11 (pytest 241건 포함), 통과 11, 실패 0 → 최종 **PASS** (재시도 3회)
- **도식 80 항목 전부 에이전트 구현** — `coverage: 전체 80/80 · 엄격 43/43`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-09 | PASS | `make test` 241 passed |
| F-01 | PASS | worker `job redteam → allow, regressions 0` · `job governance → block, hits 3` |
| F-02 | PASS | regulated-kr 44/44 · 관문 3회가 사건 `inc_c503…` 하나로 상관(D3, critical, findings 7, traces 3, 런북 d3.md) · 보고서 OWASP LLM 10/10·ASI 10/10·PIPA 6/6 충족, EU AI Act 5+부분1, NIST 2+부분2 · 레드팀 80종 회귀 0, ko tpr 1.0 / en tpr 0.998 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | D10 7종 매니페스트 거부 | D10 은 OWASP 대응 없음(횡단) → standards 비어 DP7 위반 | PRD §4.3 대로 NIST AI RMF + ISO/IEC 42001 매핑 | PASS |
| 1 | D10-03 미탐 `dueAt=0` | 0 이 거짓값으로 처리 | `is not None` 비교 | PASS |
| 2 | 시험 5건 실패 | 새 11종 기준선 미기록 1 · "D10 미구현" 전제 2 · 시험 비교 오류 2 | 기준선 기록, 시험 기대값을 실제 동작에 맞춤 | PASS |
| 3 | 사건 trace 수 3 ≠ 2 | 송금은 D3-01(승인)·D6-07(차단) 동시 — D3 사건에도 정상 상관 | 기대값 수정 | PASS |
| F-02 | 거버넌스 점검 X08.no-runbook | **실제 공백**: D4·D5·D6·D8·D10 런북 없음 (FR-X08) | 런북 5종 추가 → 재점검에서 해소 | round 2 PASS |

## 자체 점검이 찾은 남은 공백 (정상 탐지 — 설정·후속 과제)
- `D10-02.retention-short`: 기본 `EVIDENCE_RETENTION_DAYS=90` < regulated-kr 요구 1825일 → regulated-kr 운영 시 1825 로 설정.
- `D10-07.no-collector`: OTel 수집기 미설정(`OTEL_ENDPOINT`) — FR-P09 OTel 내보내기 미구현.
- `D10-03.empty-register`: 로컬 위험 등록부 비어 있음.

## 첨부 / Logs
- logs/make-test.txt, coverage.txt, worker-jobs.txt, f-governance.txt, f-governance-r2.txt, report-pipa.md
