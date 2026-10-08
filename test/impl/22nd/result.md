# 시험 결과 / Test Result — impl 22nd (Epic 22 조직 SSO: OIDC 인가 코드 + PKCE)
- 일자: 2026-10-06 · 대상: local compose(SQLite) + Keycloak 26.3(`idp` 프로파일) + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 11, 통과 11, 실패 0 → 최종 **PASS** (재시도 2회: E2E 사용자 전환 시 IdP 세션 잔존, 시험 계정 이름 충돌)
- `make test` **306 passed** (+ test_sso 13) · `make test-web` 7 + tsc · `make helm-lint` OK · 경로 스윕 11/11 오류 0

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T22-01 | PASS | response_type=code · code_challenge(43자, S256) · acr_values=mfa · scope openid · 교환 요청 code_verifier 포함·client_secret 없음 · 비밀번호 없는 사용자(external_id=iss#sub) · state 재사용 400 · amr otp 로도 MFA 인정 |
| T22-02 | PASS | MFA 403 · 미매핑 403 · aud·nonce·만료·iss 401 · 다른 키 “서명 불일치” 401 · PKCE 불일치 401 · redirect=http://evil.test/steal 422 · 거부는 `sso_denied` 원장 |
| T22-03 | PASS | approver → tenant_admin@default 동기화, 이전 세션 401(테넌트 변경), 그룹 해제 → 403 + 세션 회수 |
| T22-04 | PASS | 일반 계정 403 “비상(break-glass) 관리자만” · 사유 없음 400 · 사유 있음 200 · 알림 critical “비상 관리자” |
| T22-05 | PASS | 매핑 없이 사용 422 · issuer 불일치 502 · platform_admin@tenant 422 · tenant_admin·security_engineer 403 |
| T22-06 | PASS | “Realm 'aegis' imported” · acr_values_supported [pwd, mfa, …] · PKCE [plain, S256] · api → http://keycloak:8080 token·certs (OIDC_BACKCHANNEL_MAP) |
| T22-07 | PASS | 매핑 sec-soc→보안 엔지니어 · ciso-office→승인자 · garam-admins→테넌트 관리자@garam · sec-platform→플랫폼 관리자, 연결 시험 7/7(로그인 후 “kc.chris → 테넌트 관리자 @garam (acr mfa)”) |
| T22-08 | PASS | Keycloak 로그인 → OTP(LoA2) → /account “Alice Test (kc.alice) · 보안 엔지니어 · 플랫폼(모든 테넌트)”, kc.chris “테넌트 관리자 · 테넌트 garam” |
| T22-09 | PASS | kc.dave → “IdP 그룹 없음 … 로그인 거부 (SCR-A06)” · acr mfa-hw 요구 → IdP 가 LoA1 만 수행 → “MFA 필요 — acr pwd · amr [] (FR-D5-01)” |
| T22-10 | PASS | garam.admin(비밀번호·사유) → “조직 SSO 사용 중 — 비밀번호 로그인은 비상(break-glass) 관리자만” · plat.admin+사유 → /overview, 알림 “plat.admin 비상(break-glass) 로그인 — 사유: …” |
| T22-11 | PASS | 306 passed · vitest 7 · tsc · helm lint/template(OIDC_CLIENT_SECRET optional secretKeyRef) · /admin/sso·/setup·/account 등 11 경로 오류 0 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | E2E 두 번째 사용자 OTP 실패 | 콘솔 로그아웃 후에도 IdP(Keycloak) 세션 쿠키 유지 → 이전 사용자로 OTP 단계만 재요구 | 시험 스크립트가 사용자 전환 시 IdP 로그아웃 | 3 사용자 PASS |
| 1 | `make test` 1 실패 | 시험 계정 bg.admin 이 test_tenancy 부트스트랩 계정과 이름 충돌 | 시험 계정명 변경 | 306 passed |
| — | 미매핑 거부 문구 어색(“그룹 없음 이 …”) | 문자열 결합 | 그룹 없음/미매핑 문구 분리 | — |

## 설계 결정 기록
- 흐름: 콘솔 `/auth/sso` → API `GET /v1/auth/oidc/start`(state·nonce·code_verifier 는 서버 `oidc_requests`, 10분·1회용) → IdP → `/auth/callback` → API `POST /v1/auth/oidc/callback`(백채널 교환·RS256 검증) → 세션 쿠키. 브라우저에는 verifier·토큰이 오지 않는다.
- MFA: 인정 acr(기본 mfa — 요청 acr_values 로도 보냄) 또는 amr(otp·hwk·swk·mfa…). 시험 IdP 는 LoA 단계 인증(pwd=1 비밀번호, mfa=2 OTP).
- 역할은 IdP 그룹이 기준 — 로그인마다 동기화, 매핑 해제·MFA 미충족·테넌트 변경 시 기존 세션 회수. 로컬 계정과 같은 이름이면 거부(탈취 방지).
- SSO 사용 중 비밀번호 로그인은 break_glass 계정만, 사유 필수 → 원장 + critical 알림. SSO 설정·매핑·연결 시험은 플랫폼 관리자 전용(PLATFORM_ONLY).
- 클라이언트 비밀은 DB 에 두지 않음(OIDC_CLIENT_SECRET, 헬름 secret optional). 시험 사용자 비밀번호·TOTP 비밀은 `make idp-up` 이 생성(infra/keycloak/import, 비커밋).
- 후속: IdP 로그아웃 연동(RP-initiated), 패스키·DPoP 바인딩(SCR-B02 #3·#7) — 이번 범위 밖.
- 시험 후 로컬 SSO 는 꺼 둠(다른 차수 E2E 가 로컬 비밀번호 계정 사용). 매핑·이력은 유지.

## 로그
- logs/make-test.txt · make-test-web.txt · e2e-a-config.txt · e2e-b-sso-login.txt · e2e-c-password-mfa.txt · e2e-c2-password-denied.txt · route-sweep.txt
