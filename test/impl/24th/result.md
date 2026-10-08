# 시험 결과 / Test Result — impl 24th (Epic 24 판정 품질·오탐 예산)
- 일자: 2026-10-06 · 대상: pytest(SQLite) + local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 1회: 새 탐지 규칙 신뢰도와 단계(partial) 의미 충돌)
- `make test` **315 passed** (+ test_quality 4) · `make test-web` 7 + tsc · 경로 7/7 오류 0
- 측정이 찾아낸 결함 2건을 고치고 재측정: **d6-07 골든셋 오탐 26%(조회 도구) → 0%**, **합성 인젝션 코퍼스 미탐 61.8% → 5.9%**

## 측정 결과
| 지표 | 목표 | 결과 | 비고 |
|------|------|------|------|
| 골든셋 1만 건 오탐률 (NFR-Q1) | ≤ 0.5% | **0.00%** (합성 10,000) · 편입 표본 1건은 여전히 d1-06 변환 | 첫 측정에서 d6-07 이 조회 도구(get_order) 2,980건 중 775건(26%)을 금전 행동으로 승인 요구 → 조회 동사 제외 수정 |
| 인젝션·탈옥 코퍼스 미탐률 (NFR-Q2) | ≤ 10% | **5.9%** (34건 중 2) | 수정 전 61.8% — 직접 지시 덮어쓰기 15/21·프롬프트 추출 3/3 미탐. 남은 2건 = 내용 안전(유해 요청) 범주, D1 범위 밖 |
| 재생 시간 | — | 10,001건 × 인라인 48종 2.1초 | |

> 코퍼스 수치는 **이번에 합성한 34건**(JailbreakBench·garak 형식) 기준이다. 탐지 규칙과 코퍼스를 같은 손이 만들었으므로 낙관적일 수 있다 — 운영에서는 공개 코퍼스(JailbreakBench·HarmBench·garak 프로브)를 폐쇄망 파일로 반입해 같은 화면에서 측정한다. 공개 데이터셋 자체는 저장소에 넣지 않았다(라이선스·공격 자산 분리).

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T24-01 | PASS | 교차 재판정: 마스킹 표본에 원 에이전트 allow(재현 안 됨) · 같은 계열 합의 · 응답 hasSample=true, 표본 본문 없음 · 중복 409 · allow 판정 이의 422 |
| T24-02 | PASS | 본인 결정 403 · 다른 사람 fp → gld_… 편입(source=appeal:lbl_…) · 원장 appeal_received·appeal_decided (테넌트 체인) |
| T24-03 | PASS | d1-06 확정 오탐 누적 → 80%: 상태 warn + 제안 “D1-06 임계 → 신뢰도+0.01” YAML · 초과: alert_only, 같은 입력 block→alert(사유 ‘agent alert_only’) · 알림 ‘오탐 예산’·‘강등’ · 복귀 조건 충족 → restored·active |
| T24-04 | PASS | samples ≥ 10,000 · 에이전트 48 · overallFpRate 0 · overTarget [] · ko/en 분해 · 검수 표본 ≤30 · 테넌트 관리자 403(quality.run 플랫폼 전용) |
| T24-05 | PASS | 범주별: direct-override 0% · jailbreak 0% · harmful-behavior 100% · 원장에 sha256 만, 페이로드 문자열 없음 · CSV(Goal/Category) 인식 · 프롬프트 열 없음 422 · 테넌트 관리자 403 |
| T24-06 | PASS | d6-07 1.0.1(조회 동사 get_/list_/search_/… 제외, 골든 11·FP 0·공격 10 탐지 1.0) · d1-03 1.0.1(직접 덮어쓰기 en/ko·프롬프트 추출·‘제한이 없는’ 띄어쓰기, 골든 14·FP 0·공격 15 탐지 1.0) |
| T24-07 | PASS | eng.kim 이의(교차 재판정: d1-06 transform, 같은 계열 1종 benign) → 본인 화면 “다른 사람이 결정” → garam.admin 오탐 확정·골든셋 gld_73a3… · 신뢰 지표 이의율 7일·오탐 추이 · plat.admin 1만 건 재생 2,094ms · 코퍼스 파일 반입 5.9% · 콘솔 오류 0 |
| T24-08 | PASS | worker 기동 직후 qcheck fp_budget_checked 기록 (주기 5분), 골든셋은 주간 |
| T24-09 | PASS | 315 passed · vitest 7 · tsc · /observability/slo·/findings/{id} 등 7 경로 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 측정 | d6-07 골든셋 오탐 26% | 도구 이름에 ‘order’ 가 있으면 금전 행동으로 보고 금액 미상 → 승인 요구 (get_order 같은 조회 포함) | 조회 동사 접두 제외 + 골든 표본 편입, 버전 1.0.1 | 0% |
| 측정 | 인젝션 코퍼스 미탐 61.8% | D1-01 은 간접(검색 문서)만, D1-03 은 DAN·개발자 모드 위주 — 사용자 입력의 직접 지시 덮어쓰기·프롬프트 추출이 빈칸 | D1-03 에 override·ko-override·prompt-extraction 규칙(신뢰도 0.88/0.86) + 공격·골든 표본 | 5.9% |
| 1 | test_gate partial 단계 기대 alert → block | 새 override 규칙 신뢰도 0.9 가 partial 차단 기준(0.9)과 같음 | 일반 문구 규칙은 보안 문서 오탐 위험(§13.5)이 있어 0.88 로 — enforce 차단·partial 경보 | 315 passed |

## 설계 결정 기록
- 대체 엔진: 모든 에이전트가 엔진 1개 → “교차 재판정” = 마스킹 재현 표본을 원 에이전트 현 버전 + 같은 계열·관문 에이전트로 재판정한 합의. 원문 자동 보존 없음 — 표본은 신청자가 직접 마스킹해 넣은 것만, 오탐 확정 시에만 골든셋 편입.
- 오탐 예산은 플랫폼 전역(에이전트 상태가 전역) — 하루 예산 = max(FP_BUDGET_MIN, 인라인 판정 × 0.5%). 80% 경보는 에이전트·일당 1회, 초과 시 alert_only(차단 안 함), 강등 후 FP_RECOVER_DAYS(7)일 오탐률 ≤ 0.5% 면 자동 복귀. R5 심사 강등은 자동 복귀 대상 아님.
- 임계 제안은 정책 YAML 조각으로만 — 적용은 정책 편집기(단위 시험·2인 승인 롤백 경로 그대로).
- 권한: 이의·결정 quality(플랫폼 관리자·보안 엔지니어·테넌트 관리자) · 골든셋 재생·예산 점검 quality.run(플랫폼 전용) · 코퍼스 반입 redteam(플랫폼 전용, 공격 자산).

## 로그
- logs/make-test*.txt · make-test-web.txt · e2e-quality.txt · e2e-finding.txt · synthetic-corpus.jsonl · corpus-result.txt · corpus-before-fix.txt · quality-ledger.txt · route-sweep.txt
