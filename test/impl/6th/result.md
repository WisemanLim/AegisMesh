# 시험 결과 / Test Result — impl 6th (Epic 6 콘솔 + 완료 게이트)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite, web dev) + prod 리허설 (PostgreSQL 17, web standalone) · 커밋: —
- 스택: Next.js 15.5.27 · React 19.3.0 · Tailwind 4 · vitest 3.2.7 (pnpm 10.12.1, lockfile 커밋)

## 요약 / Summary
- 전체 12, 통과 12, 실패 0 → 최종 **PASS** (재시도 1회 — 시험 스크립트 결함)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01 | PASS | vitest 7 passed |
| U-02 | PASS | `make test-web` exit 0 (vitest + tsc) |
| F-01 | PASS | /overview /risk-map(+item) /catalog /catalog/d1-05 /instant /findings /findings/{id} /approvals /evidence(+check) /coverage → 200, /catalog/zz-99 → 404 (logs/f-pages.txt) |
| F-02 | PASS | 원장 화면 버튼은 "서명 묶음 내보내기"·"전 구간 검증 실행"뿐, MSG-016 고지 |
| F-03 | PASS | `ops.lee(self) form disabled: True`, `dev.kim disabled: True True` |
| F-04 | PASS | `auditor disabled: True True` |
| F-05 | PASS | `실패 422: 사유 입력 필수` |
| F-06 | PASS | `pending (1/2)` → `approved (2/2)`, 원장 `['requested','decided','decided']` |
| F-07 | PASS | `rejected` |
| F-08 | PASS | `적용됨 … 에이전트 1종 · 미구현 33항목` (minimal-visibility, observe) → `해제됨`, 활성 목록에서 제외 |
| F-09 | PASS | `303 …/evidence ['principal=auditor.park','lang=en']`, en 화면 "Evidence ledger"·"Append-only" |
| F-10 | PASS | api·db·web healthy · 관문 input block / tool block·require_approval / output transform (각 < 1ms) · `ledger verify True 536 6` · 엄격 19/19 · 콘솔 8화면 200 · 콘솔 내보내기 → `OK 레코드 536건 … 체인·서명 검증 통과` |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 콘솔 승인 제출이 API 404 | **시험 스크립트 결함**: 정규식이 hidden `id` 값을 못 읽어 빈 id 로 제출 | 입력 태그 속성 파서 교체 | round 2 PASS |
| 1 | (부수) 진단용 직접 API 호출이 apr_dda53805ff7a 에 sec.choi 승인 1건을 남김 | 로컬 시연 데이터 | 결과에 기록, 이후 같은 건은 lead.han 거절로 종결 | — |
| 2 | 거절 메시지가 `(2/2)` 로 승인 완료처럼 보임 | 결정 수 전체를 표기 | `승인 n/필요` 로 표기 | 수정 |
| 2 | 무결성 패널 "해시 체인 체인 검증 통과" | 문구 중복 | "해시 체인 — …" | 수정 |

## 한계
- 실제 브라우저 렌더(레이아웃·CSS·JS 하이드레이션) 시각 확인은 **MANUAL** — Claude in Chrome 확장 연결 후 `/overview`·`/risk-map`·`/approvals` 육안 점검 필요.
- 화면 101종 중 P0 핵심 7영역만 구현. 로그인(SSO)·명령 팔레트·사건 그래프·D1~D10 스쿼드 화면·미리보기 재생은 후속.
- Pretendard 로컬 폰트 파일 미번들 — 시스템 글꼴 대체(폐쇄망 요건 NFR-C3 상 폰트 파일 동봉 필요).

## 첨부 / Logs
- logs/test-web.txt, make-test.txt, f-pages.txt, f-interactions.txt, prod/{prod-build,migrate,seed,ps,smoke}.txt
