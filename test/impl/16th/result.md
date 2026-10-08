# 시험 결과 / Test Result — impl 16th (Epic 16 워크로드 신원·비밀)
- 일자: 2026-10-06 · 대상: local (SQLite, 0007→0008) + prod 리허설 (PostgreSQL 17, 0008 + RLS secret_leases) · 커밋: —
- 브라우저: 헤드리스 Chromium (gstack browse)

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (설계 수정 1회: SVID 무효화 방식)
- `make test` **270 passed** (+ test_identity 6) · `make test-web` 7 + tsc · coverage 80/80 · ruff(F,E9) clean

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T16-01 | PASS | worker 첫 주기 `job identity rotated 84` (에이전트 80 + 플랫폼 4), 원장 svid_rotated (local·prod) |
| T16-02 | PASS | 발급 시각을 31분 전으로 돌린 3개 → 다음 주기 `rotated 3`, 회전 수 0→1, 나머지 그대로 |
| T16-03 | PASS | 컨테이너에서 JWKS 만으로 Ed25519 서명 독립 검증 OK · sub `spiffe://aegismesh.local/tenant/garam/svc/svc.gw` · aud aegismesh · 수명 3600 |
| T16-04 | PASS | 서비스 API 토큰(1일) → SVID 교환 → `judge:batch` allow(default@v5), 조회 403. pytest: 변조 서명·대상 불일치·사람 사용자 교환 거부, 에이전트 SVID 는 API 주체 불가(403) |
| T16-05 | PASS | 콘솔 임대 1회 표시(40자) · 요청 7200초 → 900초로 절단 · 목록에 원문 없음 · db:read active / db:write “범위 밖(다운스코핑)” / nuri 범위 “알 수 없는 시크릿” · 콘솔 회수 → revoked |
| T16-06 | PASS | 콘솔 “즉시 전체 회전” → SVID 85 무효화·재발급 84·임대 회수 1 → 기존 SVID 401, 재교환 SVID 200, 기존 임대 revoked, 원장 (force True, plat.admin) |
| T16-07 | PASS | 정적 자격증명 1건(svc.gw `gateway-e2e` 만료 없음) → 콘솔 폐기 → 세션 회수 |
| T16-08 | PASS | 270 passed · prod: 0008, 84 SVID 자동 발급, secret_leases RLS (garam 1 · nuri 0 · 미설정 0, RLS+FORCE), 격리 시험 7/7 (secret_leases 포함으로 확장) |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 설계 | 최초 설계: 검증 시 현재 jti 만 유효 | worker 정기 회전이 서비스 계정 스스로 받은 SVID 를 50% 시점에 무효화, 복제본끼리 서로 무효화 | `valid_after` 기준으로 변경 — 정기 회전은 이전 SVID 를 만료까지 유지(SPIRE 와 같음), 즉시 전체 회전만 일괄 무효화 | T16-06 PASS |
| — | SQLite 에서 만료 시각이 시간대 없이 출력 | 조회 후 naive datetime | 출력 시 UTC 부여 | 확인 |
| — | 격리 시험 표 목록에 secret_leases 누락 | 새 테넌트 표 | TENANT_TABLES·MODELS 에 추가 | pytest PASS |

## 설계 결정 기록
- SPIRE·OpenBao 는 이 설치에 없으므로 내장 발급자(SPIFFE JWT-SVID, EdDSA, JWKS 공개 번들)와 내장 임대 브로커로 같은 계약을 제공한다. 외부 SPIRE·OpenBao 연동 시 발급·introspect 만 교체.
- SPIRE 노드 증명(attestation)은 범위 밖 — 서비스 계정은 (만료 있는) API 토큰으로 SVID 를 교환한다. 만료 없는·30일 초과 토큰은 정적 자격증명으로 표시.
- 에이전트·플랫폼 SVID 는 회전 기록(jti·만료)만 남기고 토큰 전달은 워크로드 API 역할(외부)로 둔다 — 원문 토큰은 저장하지 않는다.

## 첨부 / Logs
- logs/ (비커밋): t16-*.txt, jwks.json, 스크린샷 2장, regression·prod (svid·임대·서비스 토큰은 600 파일)
