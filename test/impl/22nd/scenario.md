# 시험 시나리오 / Test Scenario — impl 22nd (Epic 22 조직 SSO: OIDC 인가 코드 + PKCE)
- 근거: FR-D5-01(취약 인증 — 정적 비밀번호·공유 키 금지) · FR-D5-03(세션) · SCR-A06 ② 조직 SSO·그룹→역할 · SCR-B02 로그인
- 환경: local compose + `make idp-up`(Keycloak 26.3, 프로파일 idp, 렐름·시험 사용자 생성 — 비커밋) · 헤드리스 Chromium

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T22-01 | 단위 — 흐름 | 가짜 IdP(RS256)로 start → callback | 인가 URL: code·S256 challenge·acr_values=mfa·state·nonce, 교환에 code_verifier(비밀 없음), 세션·역할, state 1회용 | P0 |
| T22-02 | 단위 — 거부 | MFA 없음 · 미매핑 그룹 · aud·nonce·exp·iss 불일치 · 다른 키 서명 · PKCE 불일치 · 외부 redirect | 403/401/422 + `sso_denied` 원장 | P0 |
| T22-03 | 단위 — 동기화 | 같은 sub 로 그룹 변경·해제 | 역할·테넌트 동기화(`sso_roles_synced`), 테넌트 변경·매핑 해제 시 기존 세션 회수 | P0 |
| T22-04 | 단위 — 비밀번호 | SSO 켬 → 일반 계정 / 비상 관리자 사유 없음·있음 | 403 / 400 / 200 + `break_glass_login` 원장 + critical 알림 | P0 |
| T22-05 | 단위 — 설정 | 매핑 없이 켜기 · issuer 불일치 · 플랫폼 관리자 테넌트 매핑 · tenant_admin 접근 | 422 / 502 / 422 / 403 | P0 |
| T22-06 | IdP 기동 | `make idp-up` | 렐름 aegis 반입, discovery acr pwd·mfa, PKCE S256, api 백채널(keycloak:8080) 조회 | P0 |
| T22-07 | 콘솔 설정 | /admin/sso Issuer·Client·매핑 4건·사용·연결 시험 | 원장 기록, 시험 discovery·RS256·PKCE·매핑·MFA·비밀번호 비활성 ✓ | P0 |
| T22-08 | 실 IdP 로그인 | kc.alice · kc.chris (비밀번호 + TOTP) | 보안 엔지니어(플랫폼) · 테넌트 관리자@garam 으로 콘솔 진입 | P0 |
| T22-09 | 실 IdP 거부 | kc.dave(그룹 없음) · 인정 acr 을 IdP 가 주지 않는 값으로 | 로그인 거부 화면 · “MFA 필요 — acr pwd” | P0 |
| T22-10 | 비밀번호 봉인 | garam.admin 비밀번호 · plat.admin 비상+사유 | 거부 메시지 · 진입 + 알림 “비상 관리자” | P0 |
| T22-11 | 회귀 | make test · test-web · helm-lint · 경로 스윕 | 통과 · 콘솔 오류 0 | P0 |
