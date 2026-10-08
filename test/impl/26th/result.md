# 시험 결과 / Test Result — impl 26th (Epic 26 콘솔 본문·보고서 영어)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 3회: 스윕으로 남은 한국어 추적 — 상수 표시 자리, API 라벨, 합성 문장)
- `make test` **329 passed** (+ test_i18n 2) · `make test-web` **14** (+ i18n 7) + tsc 0 · 영어 57 경로·한국어 54 경로 콘솔 오류 0
- 영어 모드 화면의 한글: **2,635 → 680 자**(r1→r4). 남은 것: 에이전트 매니페스트가 쓴 규칙 설명(d1-05·x01~x07 ≈ 430), 사건 런북 문서(112), 데이터(사람·테넌트 표시 이름, 사람이 입력한 사유, 신뢰 키 이름)

## 구현
- `lib/i18n.ts` `L()`(정확 일치 → `{n}` 패턴(잡힌 값도 번역) → " — "·" · "·", " 조각별) · `LX()`(API 값) · `nm()`(name/nameKo) · `lib/en.ts` 카탈로그 **1,198** 건(콘솔 989 + API 라벨·메시지 틀 209) · `lib/lang.tsx` LangProvider/useLang
- `scripts/i18n-codemod.mjs`(1단계: 1,057 자리 — JSX 텍스트 817·속성·문자열·템플릿·서버 액션, lang 범위 자동 확보, 재실행 안전) · `scripts/i18n-codemod-api.mjs`(2단계: API 값 자식 475 자리 → LX) · 수동 201 자리(모듈 상수의 표시 자리·배너 톤 판정 25·라우트 핸들러·메타데이터)
- 위험 영역 영어 이름(DOMAIN_EN), 판정 배지(클라이언트 컴포넌트), 오탐 예산 행 영어 이름(API name/nameKo), M1 화면 AgentCard 미리보기를 A2A v1.0 모양으로
- 보고서: 통제 카탈로그(pipa·eu-ai-act·nist)에 titleEn·versionEn, `generate(…, lang)`·Markdown 라벨·고지문 영어, `GET /v1/reports{,/fw}?lang=en`, 콘솔 보고서·내려받기가 쿠키 언어 사용

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T26-01 | PASS | vitest 7 — “다시 검증”→Verify again, " · 강등 "→" · degraded ", “기본 테넌트 증적 보존 365일 — 원장 기록”(패턴)→…365 days…, 카탈로그 전체 자리 표시자 일치·한글 0 |
| T26-02 | PASS | logs/en-sweep-r4.txt — 57 경로 오류 0, /overview·/setup/*·/install/*·/reports 등 한글 0, 남은 경로는 위 요약의 데이터·에이전트 작성 문구만 |
| T26-03 | PASS | logs/ko-sweep.txt 53/54 → 걸린 1건(/setup/first-verdict 콘솔 오류 6)은 dev 서버 첫 컴파일 시점의 일시 오류 — 재확인 4/4 OK |
| T26-04 | PASS | “Default tenant evidence retention 90 days — recorded in the ledger” · 첫 판정 “First verdict transform output · stage enforce · 8 of 14 profile agents ran” · “Install verification Passed — gates 3/3 · start-up checks 4/4 · warnings 0” |
| T26-05 | PASS | pipa en: “Personal Information Protection Act (Korea) — Control mapping report”, 통제 6건 영어, status 동일, 5 카탈로그 Markdown 한글 0 (pytest) · 콘솔 내려받기 en/ko 각각 |
| T26-06 | PASS | “D1 Injection”·“d1-06 Injection Exfiltration Detector”·nm() — profile 은 영어 이름이 없어 id |
| T26-07 | PASS | 329 passed · vitest 14 · tsc 0 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 번역 1차분 0~249 가 엉뚱한 키에 붙음 | 첫 dry-run 목록과 고정본(v1) 목록의 순서가 다름 | 고정본 기준으로 다시 작성·자리 표시자·줄바꿈 수 검사 | 0 이슈 |
| 1 | `tests: [&#123;…&#125;]` 그대로 노출 | JSX 텍스트의 숫자 엔티티 미해석 | 코드모드에서 숫자 엔티티 해석 | 표시 정상 |
| 2 | 영어 모드에 위험 영역·역할·점검 제목이 한국어 | lib/ 상수와 API 라벨은 1단계 대상 밖 | DOMAIN_EN, 2단계 LX, API 라벨 카탈로그 209 | 2,635→680 |
| 3 | 합성 문장 어순(“14 of 8 ran”) | 조각별 번역 | 한 메시지 + 자리 표시자 | 8 of 14 |
| — | 보고서 내려받기 라우트가 API 를 토큰 없이 호출 | 기존 결함(401) | 세션 토큰·테넌트·lang 전달 | en/ko 내려받기 |
| — | /setup 비상 관리자 안내가 “OIDC 설정 슬롯만” | Epic 22 이전 문구 | /admin/sso 연결 안내로 갱신 | — |

## 설계 결정 기록
- 서버 렌더에서 번역(쿠키 lang) — DOM 치환 방식은 깜박임·수화 불일치 때문에 쓰지 않았다. 한국어 원문이 메시지 ID 라 한국어 화면은 바뀌지 않는다(회귀 위험 최소).
- 번역 범위: 콘솔이 쓴 모든 문구 + API 의 고정 라벨·메시지 틀. 범위 밖(원문 유지): 에이전트 매니페스트·코어가 쓴 규칙 설명·근거 문구, 런북 문서, 사람이 입력한 이름·사유, 이벤트 자유 문장 일부. API 오류의 고정 문구는 카탈로그로 배너에서 번역.
- 새 화면 문구 절차: `node scripts/i18n-codemod.mjs` → `scripts/i18n-msgids.json` 과 lib/en.ts 비교 → 추가. 없는 키는 한국어 원문으로 보인다(깨지지 않음).

## 로그
- logs/en-sweep-r1~r4.txt(+ .lines) · ko-sweep*.txt · e2e-en-actions.txt · report-export-en.md · make-test.txt · make-test-web.txt
