# 시험 결과 / Test Result — impl 38th (Epic 38 로그인·등록 정책: 2단계 강제 · IdP 로그아웃 · L3 부재 시 경보 전용)
- 일자: 2026-10-07 · 대상: local compose + 헤드리스 Chromium + Playwright e2e · 커밋: —

## 요약 / Summary
- 전체 11, 통과 11, 실패 0 → 최종 **PASS** (재시도 5회: 승인 사유 길이 / L2 대체 철회 / 시험 OTP 단계 재사용 / 관문 RSC 반복 / 관문 405)
- `make test` 384 passed(logs/make-test.txt) · `make test-web` 14 + tsc(logs/make-test-web.txt) · 화면 E2E(logs/e2e-r4.txt) · 패스키 E2E 15/15(logs/passkey-e2e.txt)
- 측정으로 찾은 결함: **특권 역할이 2단계 없이 승인할 수 있었고**, IdP 에서 로그아웃해도 콘솔 세션이 남았으며, L3 노드가 없으면 등록이 무기한 보류됐다

## 구현
- 0017 `tenants.auth_policy` · `app/mfa.py` 정책·필수 판정·`enroll` 세션 상태·AAGUID 허용 목록 · `app/api/auth.py` `GET/PUT /v1/tenants/{tid}/auth-policy`·`POST /v1/auth/oidc/backchannel-logout`·logout `idpLogout`
- `app/sso.py` back-channel 검증·RP 로그아웃 URL · 시험 렐름 backchannel.logout.url · post.logout.redirect.uris
- `app/review.py` R4 L1 대체 + shortfall → alert_only · `POST /v1/agents/{id}:promote` → 승인 `agent_promote`
- 콘솔 `/enroll`·`/admin/auth-policy`·`/auth/gate`(route handler)·카탈로그 차단 전환 폼·계정 "필수" 표시 · `test/e2e/passkey_e2e.py` 관리자 OTP 처리

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T38-01 | PASS | test_login_policy — enrollRequired · `/v1/approvals` 401 mfa_enrollment_required · TOTP confirm 뒤 200 · 다음 로그인 2단계 · 비특권 = 권장만 |
| T38-02 | PASS | 정책 all → engineer 등록 강제 · developer PUT 403 |
| T38-03 | PASS | AAGUID 형식 오류 422 · options attestation direct·allowlist 반환 · 목록 밖(소프트 인증기 AAGUID 0) 422 “허용되지 않은 인증기”, 세션 계속 enroll |
| T38-04 | PASS | aud 불일치·nonce 포함·events 없음·다른 키 서명 → 400, 아무것도 폐기 안 함 · 정상 토큰 → revoked ≥1, 세션 401 · 같은 jti 재전송 400 |
| T38-05 | PASS | idpLogout end_session_endpoint 쿼리 확인 |
| T38-06 | PASS | test_review·test_sandbox — R4 ran L1·shortfall true · alert_only · 사유 "격리 미달(L3 없음 → L1 대체)" · 마켓플레이스 설치도 alert_only |
| T38-07 | PASS | developer 403 · promote → approvalRef · 2인 승인 → active · 재요청 409 · 이후 판정 정상(transform) |
| T38-08 | PASS | test_l2_agent_held 유지 |
| T38-09 | PASS | appr.one → /enroll?next=%2Foverview → OTP 등록 → /overview · /approvals 정상 · 계정 "필수 (특권 역할·테넌트 정책)" · 다음 로그인 OTP |
| T38-10 | PASS | garam all 저장 → eng.kim /enroll(테넌트 정책 사유) · 되돌림 → /overview · en 한글 0(등록·정책 화면) |
| T38-11 | PASS | 15/15 — 새 위치 → /reauth → 패스키 재인증 → /approvals, 탈취 토큰 401 + 사건 |

## 회차 / Rounds
- round 1: 승인 사유 "다시" 422(최소 길이) → 시험 사유 수정
- round 2: L3 부재 시 L2 대체 실행 → 실행 시 격리 시작 거부와 충돌(§8.6 하향 금지) → L1 대체 + alert_only 로 한정, L2/L3 요구 에이전트는 보류 유지
- round 3: 브라우저와 도우미가 같은 OTP 시간 단계 사용 → 서버가 재사용 거부(정상) → 시험 도우미가 사용자별 마지막 단계를 공유
- round 4: `/enroll` 소프트 이동 시 RSC 재요청 반복 → `/auth/gate` route handler(303) → URL 이 관문에 남아 서버 액션 POST 405 → HTML `location.replace` 로 전체 이동
- round 5: plat.admin 이 OTP 등록 상태가 되어 패스키 E2E 관리자 로그인 실패(KeyError 'token') → ADMIN_TOTP 로 2단계 처리

## 남은 것 / Notes
- AAGUID 는 인증기 자기 신고 값(인증서 체인 미검증) — 허용 목록은 정책 신호, 하드웨어 증명 아님.
- 시험 부산물: appr.one 세션 탈취 사건 1건(불완전 쿠키로 보낸 시험 요청), 시험 사용자 appr.enroll·appr.loop.
- live DB 에 api 출처 alert_only 에이전트가 없어 차단 전환 화면은 pytest 로만 확인.
