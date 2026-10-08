# 시험 시나리오 / Test Scenario — impl 38th (Epic 38 로그인·등록 정책: 2단계 강제 · IdP 로그아웃 · L3 부재 시 경보 전용)
- 근거: PRD.md OQ3(특권 역할 2단계 강제)·OQ2(L3 없음 → L1 대체 + 경보 전용) 결정(2026-10-07) · 원본 PRD FR-D5-01·03, §8.6(격리 하향 금지), R07(2인 승인) · SCR-B02.
- 방식:
  - 2단계 강제 — platform_admin·tenant_admin·approver 는 수단이 없으면 로그인 세션이 `enroll` 상태(등록 경로만 허용, 나머지 401 `mfa_enrollment_required`). 테넌트 정책 `mfa: all` 로 전원 강제, `aaguids` 허용 목록이면 direct attestation + AAGUID 확인. SSO·서비스 계정 제외.
  - IdP 로그아웃 — OIDC back-channel logout(`logout_token` RS256·iss/aud·iat·events·nonce 없음·jti 재사용 거부) → 그 사용자 세션 전부 폐기. 콘솔 로그아웃은 SSO 세션이면 `idpLogout`(end_session_endpoint) 반환.
  - 등록 R4 — L3 노드가 없으면 L1 으로 대체 실행하고 `isolation.shortfall` 기록, 결과는 `alert_only`. 차단 전환은 `POST /v1/agents/{id}:promote` → 2인 승인 `agent_promote`. 실행 시 L2/L3 를 *요구*하는 에이전트는 그대로 보류(격리 하향 금지).
  - 콘솔 관문 — `reauthRequired || enrollRequired` 면 `/auth/gate` 가 HTML `location.replace` 로 전체 페이지 이동(소프트 이동 RSC 재요청 반복 방지).
- 환경: local compose + 헤드리스 Chromium(gstack browse) + Playwright e2e 서비스(가상 인증기) · plat.admin · appr.one(approver) · eng.kim(security_engineer) · 시험 Keycloak 렐름 설정

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T38-01 | 특권 역할 등록 강제 | 수단 없는 approver 로그인 | `enrollRequired`, 등록 외 API 401, TOTP 등록 → 세션 해제·원장 기록 | P0 |
| T38-02 | 테넌트 전원 강제 | garam `mfa: all` | 일반 사용자도 등록 강제, 정책 변경은 user.admin 만 | P0 |
| T38-03 | AAGUID 허용 목록 | 목록 밖 인증기 등록 | 422 + 원장 `mfa_rejected`, attestation direct | P1 |
| T38-04 | back-channel logout | 서명 logout_token, 재사용·위조 | 세션 전부 폐기·원장 기록, 재사용·서명 불일치 거부 | P0 |
| T38-05 | RP 로그아웃 | SSO 세션 logout | `idpLogout` = end_session_endpoint + id_token_hint·post_logout_redirect_uri | P1 |
| T38-06 | L3 부재 → 경보 전용 | L3 요구 등록, L3 노드 없음 | R4 L1 대체·shortfall, 상태 alert_only, 사유 표시 | P0 |
| T38-07 | 차단 전환 | `:promote` | 2인 승인 뒤 active·원장 promoted, 승인 전 상태 유지 | P0 |
| T38-08 | 격리 하향 금지 | 실행 시 L2 요구 에이전트 | 그대로 review_hold | P0 |
| T38-09 | 콘솔 등록 흐름 | appr.one 브라우저 로그인 | 관문 → `/enroll` → TOTP 등록 → 원래 화면, 다음 로그인 OTP, 계정 화면 "필수" | P0 |
| T38-10 | 콘솔 테넌트 정책 | plat.admin `/admin/auth-policy` 저장 | eng.kim 등록 강제(사유 표시) → 되돌리면 정상 로그인, en 한글 0 | P1 |
| T38-11 | 패스키·재인증 회귀 | `make e2e-passkey` | 15/15 (관문 경유 `/reauth` 포함) | P0 |
