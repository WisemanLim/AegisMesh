# 시험 결과 / Test Result — impl 13th (Epic 13 다중 테넌시·사용자·역할·로그인)
- 일자: 2026-10-06 · 대상: local (SQLite, dev — 기존 DB 0005→0006 이관) + prod 리허설 (PostgreSQL 17, runtime, API 8000·WEB 3000) · 커밋: —
- 브라우저: Claude in Chrome 미연결(연결 브라우저 0개) → gstack `browse` 헤드리스 Chromium

## 요약 / Summary
- 전체 14, 통과 14, 실패 0 → 최종 **PASS** (재시도 2회: 마이그레이션 1, 콘솔 리다이렉트 1)
- `make test` **253 passed** (기존 242 + 신규 test_tenancy 11) · `make test-web` 7 passed + tsc · coverage 80/80 · ruff(F,E9) clean

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T13-01 | PASS | 토큰 없음 401 · 위조 `am1.abc.def` 401 (logs/t13-01-02.txt) |
| T13-02 | PASS | 기존 41,676건 → `legacy` 체인 동결, 전체 검증 OK (legacy·default·platform). prod PG 667건도 legacy 로 검증 OK |
| T13-03 | PASS | `/overview` → `/login` → `/setup` 자동 이동, 기동 로그 토큰으로 비상 관리자 `plat.admin` + 테넌트 garam → `/admin/tenants` 로그인 상태. 재사용 401 (prod) |
| T13-04 | PASS | 콘솔 로그인(eng.kim → 범위 garam)·로그아웃(“로그아웃됨”). API 5회 실패 401×5 → 정상 비밀번호도 423 |
| T13-05 | PASS | 콘솔에서 nuri 생성 → `pol/nuri` · `chain:nuri`, 원장(플랫폼+테넌트 체인) 기록 |
| T13-06 | PASS | 콘솔에서 tenant_admin·approver×2·security_engineer·service 생성. 자기 행 “자기 역할 변경 불가”. 테넌트 관리자 제한은 pytest(`test_roles_and_tenant_admin_limits`) |
| T13-07 | PASS | garam 주체: nuri 판정 403 · nuri finding 404 · `X-Aegis-Tenant: nuri` 403 · 조회·증적은 garam 만. garam 체인 내보내기 58건 → `aegis verify-bundle` OK. 승인자(내보내기 권한 없음) 403 |
| T13-08 | PASS | garam 정책 v2(minConfidence 0.7) → nuri 는 v1(0.5) 그대로. pytest: garam 프로파일이 nuri 관문에 바인딩되지 않음(409) |
| T13-09 | PASS | 콘솔 토큰 발급 “지금 복사하세요 — 다시 표시되지 않음”(원문은 logs 의 600 파일에만). 서비스 토큰 → tool 관문 `require_approval` · 조회 403 · nuri 403. pytest: 회수 후 401 |
| T13-10 | PASS | 콘솔 “지금 시험” 7/7 (default·garam·nuri), worker 주기 `job tenancy ok 7/7` |
| T13-11 | PASS | prod: 연결 역할 `aegis_app` (super False·bypassrls False), 8 표 RLS+FORCE, 범위 '' → 0행, nuri → 0행, 범위 밖 INSERT “violates row-level security policy”, 원장 UPDATE “append-only”, 격리 시험 rls ✓ “교차 조회 0건” |
| T13-12 | PASS | pytest `test_session_idle_timeout` — 31분 전 사용 → 401 “유휴” |
| T13-13 | PASS | 실제 로그인 승인자: appr.one 본인 요청 버튼 비활성(MSG-011), 다른 요청 `pending (승인 1/2)` → appr.two `approved (승인 2/2)`, 사유 2건 |
| T13-14 | PASS | 253 passed · vitest 7 · tsc · coverage 80/80 · prod 14 화면 콘솔 오류 0 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | local 기동 실패 — 0006 에서 `SQLite DateTime type only accepts Python datetime` | 정책 표 재생성 시 원문 SELECT 결과를 파이썬으로 옮김 → SQLite 는 시각을 문자열로 돌려줌 | `INSERT … SELECT` SQL 복사 + 새 표 이름 변경 방식으로 교체 | round 2 PASS (SQLite·PG) |
| 1 | 실패한 0006 이 빈 `tenants` 표를 남김 | pysqlite 는 첫 DDL 을 트랜잭션 밖에서 실행 → 이후 롤백돼도 남음 | 남은 빈 표(0행 확인) 삭제 후 재기동 | PASS |
| 1 | 로그아웃 후 `http://0.0.0.0:3000/login` 으로 이동 | 라우트 핸들러의 `req.url` 이 컨테이너 바인드 주소 | Host/X-Forwarded-* 기준 리다이렉트, prefs 는 같은 호스트 referer 만 허용 | round 2 PASS |
| 1 | 사용자 역할 편집에 테넌트 사용자에게도 `platform_admin` 표시 | 표시 필터 누락(API 는 422 로 거부) | 테넌트 사용자 행에서 제외 | 시각 확인 |
| — | 회귀 11건 실패(최초) | 시험이 `X-Aegis-Principal` 헤더로 주체를 바꾸던 방식 | 픽스처 `as_user(이름, 역할, tenant=)` API 토큰 + 기본 주체 `test.admin` · 미인증은 `anon` | 253 passed |
| — | prod 이미지가 0005 그대로 | `make prod-all` 은 재빌드하지 않음 | `make prod-build` 로 리허설 | 0006 (head) |
| — | 시험 도구: snapshot ref 가 `fill` 후 무효화 | browse 도구 동작 | 폼 범위 CSS 선택자 사용 | PASS |

## 설계 결정 기록
- 원장: 체인 = 테넌트(`ledger_chains`), 플랫폼 사건은 `platform` 체인, 0006 이전 레코드는 `legacy` 체인으로 동결(추가 전용 — 재체인 불가). 내보내기 묶음은 한 체인만 담아 다른 테넌트 레코드 없이 단독 검증.
- RLS 는 슈퍼유저·소유자에게 적용되지 않으므로 비특권 역할 `aegis_app` 으로 SET ROLE(풀 체크아웃 시). 범위는 트랜잭션 로컬 `aegis.tenant`, 미설정 = 0행(실패 시 닫힘).
- 화면설계(SCR-B02)는 정적 비밀번호 로그인을 금지하지만, 확인 단계 결정에 따라 로컬 계정을 초기·비상·폐쇄망용으로 두고 OIDC 는 설정 슬롯만 제공(IdP 연동·패스키·DPoP 는 후속).

## 첨부 / Logs
- logs/ (비커밋): round1/2 기동, t13-*.txt, garam-bundle.json, 스크린샷 7장, e2e-credentials.env·e2e-svc-token.env(600, 시험용)
