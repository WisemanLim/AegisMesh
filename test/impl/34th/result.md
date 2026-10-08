# 시험 결과 / Test Result — impl 34th (Epic 34 로그인 보안 강화)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium(gstack) + Playwright 1.55 Chromium·CDP 가상 인증기 · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 6회: 실패 누적 단정 / 콘솔 봉인 키가 번들마다 달라 토큰을 싣지 않음 / 스크립트 UA 혼용이 재인증을 부름 / Playwright 이미지에 Python 패키지 없음 / prod RLS 로 탈취 대응 500 / E2E 재실행 비멱등)
- `make test` **374 passed** (+ test_login_hardening 5) · `make test-web` 14 + tsc 0 · `make e2e-passkey` **15/15** · d5-03 1.1.0 골든 14·공격 13 오탐 0·탐지 1.0
- 측정으로 찾은 결함: **세션 토큰이 순수 bearer**(탈취 토큰을 그대로 재사용 가능) → DPoP 바인딩·재사용 = 전체 폐기 · **2단계 인증 없음**(정적 비밀번호만) → 패스키 우선·OTP 대체 · **D5-03 가 소유 증명을 보지 않음** → `token-replay`

## 구현
- `app/webauthn.py`(최소 CBOR·COSE·등록·assertion 검증 — challenge 1회·origin·rpIdHash·UP·UV·서명·카운터 역행), `app/dpop.py`(RFC 9449 증명 — typ·alg ES256/EdDSA·jwk(개인키 거부)·서명·iat ±60s·jti·htm·htu 경로·ath, RFC 7638 지문), `app/mfa.py`(OTP RFC 6238 봉인·재사용 금지, 대기표, 등록·assertion 옵션, 요청마다 증명·기기·위치 검사, 탈취 대응·재인증)
- 마이그레이션 0014: `webauthn_credentials`·`mfa_challenges`·`dpop_jti`, users(totp_*), auth_sessions(jkt·mfa·device·device_hash·location·state·review_reason)
- API: `/v1/auth/login`(2단계면 `{mfa}`) · `/v1/auth/mfa:verify` · `/v1/auth/mfa` · `/v1/auth/webauthn/register{:options,}` · `DELETE /v1/auth/webauthn/{id}` · `/v1/auth/totp{:setup,:confirm}` · `/v1/auth/reauth{:options,}` · `/v1/auth/sessions:revoke-others` · `/v1/auth/me`(reauthRequired·binding) · `ctx` 가 세션마다 `mfa.enforce` · env `WEBAUTHN_RP_ID`·`WEBAUTHN_ORIGINS`
- 콘솔: `lib/dpop.ts`(세션별 P-256 키·AES-256-GCM 봉인 쿠키·증명 생성), `lib/api.ts`(모든 API 호출에 DPoP·브라우저 IP·UA, 키를 못 열면 토큰을 싣지 않음), 로그인·SSO 콜백·부트스트랩 바인딩, `/login/mfa`·`/reauth`(레이아웃 재인증 게이트, 미들웨어 경로 전달), `/account`(패스키·OTP·세션 표), `components/Passkey.tsx`, 직접 fetch 3곳(logout·prefs·reports) 공통 헤더 · env `WEB_SESSION_SECRET`
- E2E: `infra/e2e/Dockerfile`(Playwright 1.55 + Python) · compose `e2e`(local `e2e` 프로파일, 콘솔 네트워크 공유) · `make e2e-passkey` · `test/e2e/passkey_e2e.py`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T34-01 | PASS | 잘못된 origin 422 · 등록 201 · 로그인 `{mfa}`(webauthn, allowCredentials) · assertion → 세션 · 대기표 재사용 401 · 카운터 역행 “복제 의심” 401 · 다른 challenge 401 · 누적 5회 → 423 |
| T34-02 | PASS | 오답 422 · 확인 → 켜짐 · 같은 단계 코드 재사용 401 · 다음 단계 → mfa totp |
| T34-03 | PASS | binding dpop·“Chrome · macOS”·203.0.113.0/24 · iat 600초 전 401 · ath 불일치 401(아직 살아 있음) · 증명 없음 → 401 “세션 탈취” · 같은 사용자 다른 세션도 401 · 사건(D5-03.token-replay) · 원장 token_replay revoked ≥ 2 · 다른 키 401 · jti 재사용 401 “재사용” |
| T34-04 | PASS | 198.51.100.7·iPad → 401 reauth_required · me reauthRequired(◆ Chrome · macOS → Safari · iPadOS · ⌖ …) · 세션 review · 틀린 비밀번호 401 → 비밀번호 재인증 → Safari · iPadOS / 198.51.100.0/24 · fingerprint-mismatch 판정 · 패스키 등록 후 비밀번호 재인증 거부 → 패스키 재인증 200 |
| T34-05 | PASS | 다른 세션 1+ 종료 → 401, 현재 200 |
| T34-06 | PASS | logs/passkey-e2e.txt 15/15 · b02-account·mfa·reauth-ko.png — 가상 인증기 credential rpId localhost · 2단계 화면 → 패스키 → overview · 세션 “DPoP · webauthn” · X-Forwarded-For 198.51.100.23 → /reauth → 패스키 → /approvals · 새 위치로 다시 묶임 · OTP 2단계 · 쿠키 토큰 직접 사용 → 401 세션 탈취 → 브라우저 /login · 사건 inc_16a224c732c1 |
| T34-07 | PASS | d5-03 run5(증명 일치·같은 기기·묶이지 않은 bearer·바인딩 없음 / 증명 없음·다른 키·같은 기기 다른 키) 오탐 0·탐지 1.0 · en /login·/login/mfa·/reauth·/account 한글 0(남은 것 = 사용자 표시 이름) · 374 passed · vitest 14 · tsc 0 |

## 회차 / Rounds
- round 1: 잠금 단정 — 복제·challenge 실패도 누적에 들어가 3회 만에 잠김(설계대로) → 시험 횟수 수정
- round 2: 콘솔 로그인 직후 다음 화면에서 로그아웃 — `WEB_SESSION_SECRET` 이 없으면 번들(서버 액션·라우트·화면)마다 임의 봉인 키를 만들어 키 쿠키를 못 열고, 그래서 토큰을 싣지 않았다(바인딩 토큰을 증명 없이 보내 탈취로 폐기되는 것은 막힘) → 프로세스 공용 + `.next/aegis-web-secret` 보관
- round 3: 관리자 토큰을 curl 로 받고 Python 으로 쓰자 “새 기기” 재인증 — 묶이지 않은 API 세션은 도구마다 UA 가 달라 기기는 보지 않고 위치만
- round 4: Playwright Python 공식 이미지에 `playwright` 패키지가 없음 → `infra/e2e` 이미지(빌드 때만 설치)
- round 5 (prod 완료 게이트): PostgreSQL 에서 탈취 토큰 재사용이 500 이고 폐기가 롤백 — 인증 단계(범위 설정 전) 기록이 RLS(`evidence`)에 막힘 → 탈취·이상 세션 대응은 시스템 범위(`*`)로 기록. 재빌드 후 prod: 증명 200 · 증명 없음 401 + 세션 2개 폐기 · 폐기 후 401 · 원장 token_replay · 새 위치 401 reauth_required · me 200
- round 6: E2E 재실행이 첫 실행의 시험 사용자(패스키·OTP 등록됨)를 다시 써서 1단계 단정 실패 → 실행마다 새 사용자를 만들고 끝에 비활성화(재실행 15/15)

## 완료 게이트 (5차 실행) / Completion gate
- `make test` 374 passed (prod 수정 반영 후 재실행) · `make test-web` 14 + tsc 0 · `make e2e-passkey` 15/15(재실행)
- prod 회귀: `make prod-build` → `make prod-all` → `make db-migrate ENV=prod`(0012 → **0014**) → `make db-ping ENV=prod` postgres OK → 스모크(logs/prod/smoke-2.txt·smoke-reauth.txt): health ok · auth config dpop·webauthn·totp · 원장 검증 ok 1,126,571건(47s) · 새 API 8종 200(대상·비교·트레이·공정성·카드·배포 게이트·관문 상태·점검 보드) · 업데이트 80·서명 SBOM(CycloneDX 133·EdDSA) · 격리 시험 7/7 · 콘솔 /login 200 · DPoP 바인딩·탈취·재인증 → `make prod-stop` → `make local-all`

## 남은 것 / Notes
- 위치는 IP 대역(/24·/48)만 — 지오 IP·“불가능한 이동”은 외부 DB 가 필요해 하지 않았다. 운영은 콘솔 앞 프록시가 `X-Forwarded-For` 를 덮어써야 한다(브라우저가 보낸 값을 그대로 믿지 않게).
- 증명(attestation)은 'none' — 인증기 기종 신뢰(AAGUID 허용목록)는 하지 않는다. 2단계 강제(등록하지 않은 사용자 차단)는 정책 결정 사항이라 기본은 “등록 권장 배너”.
- 콘솔 인스턴스가 여러 개면 `WEB_SESSION_SECRET` 을 같은 값으로 주입해야 한다(아니면 다른 인스턴스로 간 요청은 로그아웃).
