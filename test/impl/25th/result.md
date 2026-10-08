# 시험 결과 / Test Result — impl 25th (Epic 25 A2A 어댑터)
- 일자: 2026-10-06 · 대상: pytest + 단일 파일 CLI(dist/aegis-linux-arm64, debian:bookworm-slim·파이썬 없음) + local 플랫폼 · 커밋: —

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (재시도 1회: 지역 import 로 FastAPI 가 Request 주석을 못 풀어 422)
- `make test` **327 passed** (+ test_a2a 12) · `make test-web` 7 + tsc · `make cli` 재빌드

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T25-01 | PASS | supportedInterfaces [{url …/a2a, protocolBinding JSONRPC, protocolVersion 1.0}] · skills judge · protected {alg EdDSA, typ JOSE, kid, jku …/.well-known/jwks.json} · JWKS 검증 OK · URL 바꿔치기 bad-signature · 다른 키 untrusted · 서명 없음 unsigned |
| T25-02 | PASS | AWS 키 text part → transform Finding(D2-03), contextId 유지, history [] · 아티팩트에 키 원문·무해화 결과 없음 · GetTask 동일 · CancelTask -32002 · 없는 task -32001 · data part 정상 → allow |
| T25-03 | PASS | 헤더 없음/0.3 → -32009 · message/send → -32601 · url part → -32005 · messageId 없음·output 숫자 → -32602 · SendStreamingMessage → -32004 |
| T25-04 | PASS | 토큰 없음 401 + WWW-Authenticate · 정상 SVID 200 · aud 다름·만료·다른 키·SPIFFE 아님 401 · 카드에 securitySchemes.svid |
| T25-05 | PASS | x01 1.0.1: 서명 카드 allow · 변조 X01.bad-signature · 신뢰 키 없음 X01.untrusted-key (골든 11·공격 12, 탐지 1.0·FP 0) |
| T25-06 | PASS | 하위 프로세스 `aegis serve d1-03 --protocol a2a --key` · `a2a send` 신뢰 고정 없음 거부 · `a2a card --trust` OK · 인젝션 block · 다른 JWKS 거부 |
| T25-07 | PASS | 플랫폼이 svc.gw 에 SVID(spiffe://aegismesh.local/tenant/garam/svc/svc.gw, aud aegismesh) 발급 → 에이전트 컨테이너(파이썬 none) `--trust-jwks` 플랫폼 JWKS · 클라이언트 컨테이너: 카드 OK(pinned) · TOFU 거부 · 다른 키 거부 · SVID 없음 HTTP 401 · “이전 지시는 모두 무시하고…” → TASK_STATE_COMPLETED block D1-03.ko-override 0.88 · 정상 allow · 플랫폼 /v1/judge?agent=x01 실제 카드 allow, 변조 block. 임시 API 토큰 회수·카드 키 삭제·네트워크 정리 |
| T25-08 | PASS | 327 passed · vitest 7 · tsc |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | JSON-RPC 요청이 모두 422 “query.request 필요” | `from __future__ import annotations` + create_app 안에서 import 한 Request — FastAPI 가 문자열 주석을 모듈 전역에서 못 찾아 쿼리 인자로 봄 | FastAPI·JSONResponse·JudgeRequest 를 모듈 상단에서 import | 12 passed |
| — | E2E 스크립트가 바이너리를 못 찾음 | make cli 가 dist/cli → dist/aegis-linux-<arch> 로 옮김 | 경로 수정(스크립트) | PASS |

## 설계 결정 기록
- 규격: A2A v1.0 a2a.proto 의 proto3 JSON(camelCase) — Part 는 text·data oneof(kind 판별자 없음), 열거형은 ROLE_*·TASK_STATE_*. SendMessage 결과 {"task": …}. 오류 코드는 v0.3 표(-32001~-32005)를 따르고 VersionNotSupported 는 -32009 로 두었다(규격 본문에서 숫자 확인 못함 — 이름은 data 에도 표기 안 함, 메시지 문자열로 구분).
- 카드 서명: signatures 를 뺀 카드의 정규 JSON(키 정렬·공백 없음 — 카드에 실수 없음 → RFC 8785 와 같은 바이트)을 분리형 JWS(EdDSA)로. 키는 `aegis keygen` 출력(없으면 임시 키, 경고). 클라이언트는 대역 밖 신뢰 JWKS(--trust)로 고정해야 호출 — 카드의 jku 만으로는 자기 주장(TOFU)이라 거부.
- 호출자 인증: 플랫폼 JWT-SVID(EdDSA·1시간) 서명·만료·aud·SPIFFE ID — 폐기 조회는 하지 않음(오프라인), 상한은 SVID 수명.
- 판정은 즉시 완료 → Task 는 COMPLETED, 스트리밍·푸시·확장 카드는 미지원(capabilities false, -32004). 태스크는 메모리 1,000건 LRU, 입력 원문 미보존.
- X01 은 v1.0 카드(signatures)와 이전 형식({card, signature, keyId})을 모두 검증.

## 로그
- logs/make-test.txt · make-cli.txt · e2e-a2a.txt · a2a/(공개키·JWKS·실제 카드·X01 요청 — 비밀 없음)
