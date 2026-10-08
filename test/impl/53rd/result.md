# 시험 결과 / Test Result — impl 53rd (Epic 53 SPIRE 연동)
- 일자: 2026-10-07 · 대상: local + SPIRE 1.15.3(server·agent) · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 2회: 첫 발급 전 등록 지연 / 시험 갱신)
- `make spire-up`: 신원 87개(에이전트 80·플랫폼 4·서비스 3) = SPIRE 등록 항목 87 · JWKS = SPIRE ES256 키 + 전환용 내장 Ed25519 키
- 서비스 계정 SVID 교환 → ES256·SPIRE kid → 검증 API 유효 → SVID 로 `/v1/auth/me` 200
- 즉시 회전: 87개 무효화 → 옛 SVID "즉시 회전으로 무효화된 JWT-SVID" · 새 SVID(aud 에 `aegis-gen-…` 로 에이전트 캐시 우회) 유효 · 서비스 계정 폐기 → 등록 항목 삭제
- `make spire-down`: builtin 복귀, SPIRE 가 발급한 토큰은 "알 수 없는 서명 키"로 거부 · `make test` 440 passed

## 구현
- compose `spire-server`·`spire-agent`(프로파일 spire, 이미지 1.15.3, agent 는 `pid: service:api`) · `infra/spire/server.conf`·`agent.conf`(join token·disk 키·SQLite·unix 증명, 신뢰 번들 파일로 첫 연결 검증)
- api 이미지에 `spire-agent`·`spire-server` CLI(고정 판 정적 바이너리) · `app/spire.py`(등록 항목 동기화·Workload API 발급·번들 ES256 검증·상태)
- `app/identity.py` — `IDENTITY_BACKEND=spire` 분기(발급·검증 두 서명·동기화·회전은 SPIRE 몫·상태), 첫 발급 때 항목 생성 후 에이전트 동기화 대기, 즉시 회전 뒤 세대 aud · `/v1/identity/svid` 의 kid 는 토큰 머리에서
- Makefile `spire-up`·`spire-down [ENV=prod]` · `infra/spire/api.env`·`bundle.pem` 비커밋 · prod 덧씌움 api·worker `group_add: ["0"]`(관리 소켓) · env `IDENTITY_BACKEND` · `test/test_spire.py` 4건

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 440 passed · test_spire 4 |
| C02 | PASS | spire-server healthy · agent "Node attestation was successful" · bundle.pem 로 trust_bundle_path |
| C03 | PASS | `GET /v1/identity` backend spire·algorithm ES256 (SPIRE)·spire.entries 87·counts 80/4/3 · `entry show` 87 |
| C04 | PASS | spiffe://aegismesh.local/tenant/default/svc/svc.spire · header ES256 · verify True · `/v1/auth/me` 200 |
| C05 | PASS | rotate {rotated 0, invalidated 87, backend spire} · 옛 SVID False("즉시 회전으로 무효화된 JWT-SVID — 다시 발급") · 새 SVID True(aud aegis-gen-1791376935) · 폐기 뒤 항목 없음 |
| C06 | PASS | builtin·EdDSA (Ed25519) · SPIRE 토큰 False("알 수 없는 서명 키") |

## 회차 / Rounds
- round 1: 새 서비스 계정은 등록 항목이 아직 없어 첫 발급 503 → 발급 실패 시 항목을 만들고 에이전트 동기화(약 5 s)를 최대 15 s 기다리게. SPIRE 가 아예 안 될 때만 503
- round 2: 단위 시험을 새 동작(첫 발급 자동 등록)에 맞춤

## 남은 것 / Notes
- prod 리허설의 spire-up 은 완료 게이트에서 확인(api uid 10001 선택자, 관리 소켓 그룹).
- api 를 다시 만들면 agent 도 다시 만들어야 한다(PID 네임스페이스 공유) — `make spire-up` 이 순서대로 한다.
- join token 은 1회용 — agent 데이터 볼륨에 SVID 가 남아 있으면 다시 쓰지 않는다.
