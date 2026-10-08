# 시험 시나리오 / Test Scenario — impl 34th (Epic 34 로그인 보안 강화)
- 근거: 화면설계 SCR-B02(로그인·세션 — ② 2단계 인증 WebAuthn 우선·OTP 대체, ③ 내 세션, ⑤ 이상 세션 경고 MSG-030, ⑦ 세션 정책, ⑧ 탈취 대응). PRD FR-D5-01(약한 인증)·FR-D5-03(세션 탈취 — 소유 증명 토큰·재사용 감지).
- 결정(5차 확인): 패스키 시험 = 로컬 Playwright + 가상 인증기(CDP WebAuthn).
- 방식: WebAuthn RP 검증을 `cryptography` 로 직접 구현(최소 CBOR·COSE ES256/EdDSA/RS256, attestation none, challenge 1회·origin·rpIdHash·UP·UV·서명·카운터 역행). 2단계 = 1단계 후 대기표(5분·1회) → 패스키 assertion 또는 OTP(RFC 6238, AES-GCM 봉인·같은 코드 재사용 금지). DPoP(RFC 9449) — 로그인·2단계·SSO 콜백·부트스트랩 요청의 증명 키 지문(jkt)을 세션에 기록, 이후 요청마다 htm·htu·iat(±60s)·jti(재사용 금지)·ath 검사. 콘솔은 세션마다 P-256 키를 만들어 봉인 쿠키(AES-256-GCM)로 보관, 서버에서만 증명 생성(브라우저 JS 는 키·토큰 못 봄). 탈취 = 바인딩 토큰의 증명 없음·다른 키·jti 재사용 → 사용자 세션 전체 폐기 + D5-03 `token-replay` 판정·사건 + 원장. 새 기기(브라우저·OS 계열)·위치(IP /24·/48) → 세션 review → 재인증 전까지 me·reauth·logout·sessions 만. 묶이지 않은 API 세션은 위치만.
- 환경: local compose + 헤드리스 Chromium(gstack) + `make e2e-passkey`(Playwright 1.55 Chromium·CDP 가상 인증기, 콘솔 네트워크 공유 → http://localhost:3000) · pk.user(garam, 시험 중 생성) · eng.kim

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T34-01 | 패스키 등록·2단계 로그인 | 소프트 인증기 등록(잘못된 origin 포함) → 로그인 → assertion | 잘못된 origin 422, 등록 201, 로그인 = `{mfa}`(토큰 없음), assertion → 세션, 대기표 재사용 401, 카운터 역행(복제) 401, 다른 challenge 401, 실패 누적 5회 → 423 | P0 |
| T34-02 | OTP 대체 | 설정 → 확인(오답 422) → 로그인 | 같은 코드 재사용 401, 다음 단계 코드 → 세션(mfa totp) | P0 |
| T34-03 | DPoP 바인딩·탈취 재사용 | 증명 로그인 → 정상·시각 오차·ath 불일치·증명 없음·다른 키·jti 재사용 | 정상 200, 오차·ath = 401(폐기 아님), 증명 없음 = 401 + 사용자 세션 전부 폐기 + D5-03 사건·원장 token_replay, 다른 키·재사용 = 폐기 | P0 |
| T34-04 | 새 기기·위치 재인증 | 같은 토큰을 다른 IP·UA 로 | 401 reauth_required, me 는 reauthRequired, 세션 review, 비밀번호 재인증(2단계 없을 때)·패스키 재인증(있으면 비밀번호 거부) → 새 기기·위치로 다시 묶임, D5-03 fingerprint-mismatch 판정 | P0 |
| T34-05 | 다른 세션 종료 | 세션 2개 | 다른 세션 401, 현재 세션 유지 | P1 |
| T34-06 | 브라우저 E2E (가상 인증기) | `make e2e-passkey` | 등록(create) → OTP 등록 → 2단계 화면 → 패스키 로그인 → 세션 DPoP·webauthn → 새 위치 → /reauth → 패스키 재인증 → OTP 로그인 → 쿠키 토큰 직접 사용 = 탈취 401 → 브라우저 세션 폐기 → 사건 | P0 |
| T34-07 | d5-03 엔진·영어·회귀 | run5 골든 4·공격 3, en 4 화면, make test·test-web | 오탐 0·탐지 1.0, 화면 문구 영어, 통과 | P0 |
