# 시험 결과 / Test Result — impl 12th (Epic 12 콘솔 확장 + 브라우저 E2E + prod 회귀)
- 일자: 2026-10-06 · 대상: local (SQLite, dev) + prod 리허설 (PostgreSQL 17, web standalone, API 18000·WEB 13000) · 커밋: —
- 브라우저: **Claude in Chrome 미연결**(확인 3회·재시작 후 재확인 1회, 연결 브라우저 0개) → gstack `browse` 헤드리스 Chromium 으로 대체

## 요약 / Summary
- 전체 10 (pytest 242 + vitest 7), 통과 10, 실패 0 → 최종 **PASS** (재시도 3회)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01·U-02 | PASS | `make test` 242 passed · `make test-web` exit 0 |
| F-01 | PASS | 15 경로 200 (logs/f-pages.txt), `/domains/Z9` 404, 보고서 md 내려받기 |
| F-02 | PASS | 20 화면 콘솔 오류 0 (local dev) |
| F-03 | PASS (round 2) | 요청자 dev.kim 승인 버튼 disabled · sec.choi·lead.han 클릭 → API `approved` + 사유 2건 |
| F-04 | PASS | API `closed True sec.choi` |
| F-05 | PASS | `실패 422 … 책임자·기한 필수 (MSG-003)` → `등록됨 R-bf78b6` |
| F-06 | PASS | `캠페인 완료: 80종 · 회귀 0 · X09 allow` · `자체 점검 block · 발견 3건` · `격리 해제 qtn_… (shady-mcp)` · en 셸 |
| F-07 | PASS | api·db·web·worker healthy · migrate 0003→0005 · `seed: agents 80` · coverage 80/80 · regulated-kr 44/44 · 관문 4종 판정·사건 연결 · 보고서 OWASP LLM 10/10·ASI 10/10·PIPA 6/6 · 레드팀 80 회귀 0 · `ledger verify True 661` · 묶음 `OK 661건` |
| F-08 | PASS | prod 22 화면 콘솔 오류 **0** · 승인 `pending (승인 1/2)` → `approved (승인 2/2)` · `적용됨 … 34종 · 미구현 0항목` |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | **승인 버튼 클릭 시 422** (실제 브라우저에서만) | JS 실행 환경의 서버 액션 FormData 에 누른 버튼의 name/value 가 실리지 않음. 6차의 JS 없는 폼 제출 시험은 값을 직접 넣어 가려졌다 | 승인·거절을 버튼별 `formAction` 서버 액션으로 분리 | round 2 PASS (local·prod) |
| 1 | 사건 타임라인 무한 누적 | 30초 주기 점검이 같은 위반을 찾을 때마다 판정 추가 | offline 관문 재점검은 새 규칙이 없으면 갱신 시각만 반영 + 시험 추가 | PASS |
| 1 | 개요 "보강 X" 가 X05 만 집계 | 키 하나만 조회 | X01~X10 합산 | PASS |
| 1 | 증적 원장 요약이 새 레코드 종류를 JSON 으로 표시 | 요약 함수가 6종만 처리 | scan·quarantine·incident·redteam·risk·report·governance·agent 요약 + 필터 | PASS |
| 1 | 사건 그래프 노드 글자가 원 밖으로 넘침 (`d10-02`) | 원 반지름 18 | 26 으로 확대 | 시각 확인 |
| — | 위험 등록 첫 시험 실패 | **시험 타이밍**: 리다이렉트 재렌더 전에 입력 → 값 유실 | URL 변화 대기 후 입력 | PASS |
| F-07 | prod 기동 시 포트 8000 충돌 | **사용자의 다른 프로젝트 컨테이너(wise-agentnexus)가 8000 점유** — 정지하지 않음 | 이번 리허설만 `API_PORT=18000 WEB_PORT=13000` (셸 env 가 env 파일보다 우선) | PASS |

## 관찰 (재현 불가)
- local dev 에서 하이드레이션 경고 2회 관찰 — 파일 수정 직후 핫리로드·서버 액션 리다이렉트 직후 연속 이동 시. fresh load 30회+ 와 **prod 빌드 22 화면·흐름에서 0건** → dev 전용 일시 현상으로 판단.

## 한계
- **Chrome 확장 기반 검증 미수행** — 헤드리스 Chromium 으로 대체(같은 Blink 엔진, JS 실행·클릭·스크린샷). 사용자의 실제 Chrome 환경 차이(확장·폰트)는 미확인 → MANUAL.
- 영어(en) 모드는 셸·메뉴·공통 문구만 번역, 화면 제목·본문은 한국어(NFR-C4 부분 충족).
- 101 화면 중 핵심 위주 구현(로그인 SSO·명령 팔레트·미리보기 재생 등 미구현).

## 첨부 / Logs
- logs/f-pages.txt, shots/01~09-*.png (local), prod/{prod-build,migrate,seed,ps,smoke,worker,browser-pages}.txt, prod/p-*.png
