# 시험 결과 / Test Result — impl 41st (Epic 41 OpenBao 시크릿 백엔드)
- 일자: 2026-10-07 · 대상: local compose + OpenBao 2.4.1(dev, `bao` 프로파일) · 커밋: —

## 요약 / Summary
- 전체 12, 통과 12, 실패 0 → 최종 **PASS** (재시도 1회: 시험 OTP 시간 단계 충돌)
- `make test` 392 passed(logs/make-test.txt — `test_openbao` 4) · `make test-web` 15 + tsc · 실제 OpenBao E2E(logs/e2e.txt · e2e-outage.txt) · 콘솔(identity-ko.png · identity-en.png)
- 측정으로 확인한 것: 반복 갱신도 **생성 시각 기준 15분**을 넘지 않는다(6초 뒤 갱신 → 894초, 10초 뒤 → 890초 — 역할 `token_explicit_max_ttl` 적용. 토큰 조회의 `explicit_max_ttl` 표시는 0 이지만 실제로 막힌다)

## 구현
- `app/openbao.py`(urllib, 토큰 역할 발급·accessor 조회·갱신·회수·상태) · `app/secrets_broker.py` 엔진 분기(발급·갱신·회수·전체 회수·introspect 가 OpenBao 원본 확인, 회수·만료 동기화, fail-closed) · `GET /v1/secrets/backend`
- 0018 `secret_leases.backend`·`accessor` · 설정 `SECRETS_BACKEND`·`OPENBAO_ADDR`·`OPENBAO_TOKEN` (.env.local·.env.prod(CHANGE_ME)·.env.example)
- compose `bao` 서비스(local, 127.0.0.1:`BAO_PORT`=8210 — 8200 은 다른 프로세스 사용 중) · api·worker 선택 env_file `infra/openbao/api.env` · `scripts/bao_setup.py` · `make bao-up`·`bao-down` · `.gitignore` `infra/openbao/*.env`
- 콘솔 `/admin/identity` 임대 엔진 상태·임대별 엔진 열

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T41-01 | PASS | configure ok — OpenBao 2.4.1 · role aegis-lease (explicit max 900s) · `{'backend': 'openbao', 'sealed': False, 'ok': True}` |
| T41-02 | PASS | lse_8bd33be9a208 — 원문 `s.`(26자) · expiresAt = issuedAt + 15분 · meta {holder, lease, path garam/db/orders-ro, scopes, tenant} · 응답에 accessor 없음 |
| T41-03 | PASS | lookup-self → policies [aegis-lease-holder] · sys/policies/acl → 403 |
| T41-04 | PASS | active · backend openbao · ttl 898 / db:write → 범위 밖 |
| T41-05 | PASS | renew → renewals 1 · OpenBao ttl 599 · 반복 갱신 894·890초(생성 기준 상한) |
| T41-06 | PASS | state revoked · 보유자 lookup-self 403 · introspect revoked |
| T41-07 | PASS | `bao token revoke -accessor` → introspect "OpenBao 에서 회수·만료됨" · 목록 revoked/revokedBy openbao · 원장 lease_revoked(by openbao) |
| T41-08 | PASS | ttl 29 → 33초 뒤 보유자 403 · introspect expired |
| T41-09 | PASS | 중지 → introspect active false(확인 불가) · 발급 HTTP 503 · backend ok false |
| T41-10 | PASS | 재기동·`make bao-up` → 옛 임대 "OpenBao 에서 회수·만료됨" · 새 임대 active / `make bao-down` → builtin(aeg_dyn_) active · OpenBao 임대 거부(브로커 토큰 없음) |
| T41-11 | PASS | ko "임대 엔진: OpenBao 2.4.1 http://bao:8200 · 정상 — …" · en "Lease engine: OpenBao 2.4.1 … healthy — …" · 'OpenBao 회수'/'revoked in OpenBao' · 위반 0 · en 한글 0 |
| T41-12 | PASS | 392 passed |

## 회차 / Rounds
- round 1: 장애 시험의 관리자 로그인 401 "OTP 코드 불일치" — 직전 화면 캡처 스크립트가 같은 사용자의 다음 시간 단계를 먼저 써서 서버가 재사용 거부(정상) → 시험 도우미 단계 기록을 올린 뒤 재실행 PASS

## 남은 것 / Notes
- 운영: OpenBao 는 외부 클러스터(봉인 해제·감사 장치·HA)를 `OPENBAO_ADDR` 로 가리킨다. 브로커 토큰은 주기(period) 토큰 — 갱신·회전은 운영 절차(이번 차수는 dev 서버 리허설만).
- dev 서버는 메모리 저장 — 재기동하면 그때까지의 OpenBao 임대가 모두 무효가 된다(확인은 거부로 맞춰진다).
- 기본값은 `SECRETS_BACKEND=builtin` — 시험 뒤 `make bao-down` 으로 내장 브로커 상태로 되돌려 두었다.

## 완료 게이트 (6차 실행, logs/gate/)
- `make test` 392 passed · `make test-web` 15 + tsc · `make contract-update` 213 → **218 작업**(추가만 — auth-policy GET·PUT, back-channel logout, agents:promote, secrets/backend) · 계약 시험 2 passed
- 전 경로 접근성·영어(run.txt): **256쪽 axe serious·critical 0**, 74 틀 중 73 도달(`/domains/[d]/inspect/[fid]` 은 39차 run-r5 에서 점검) — en 관문 2건 새로 발견: ① 판정 근거 메모의 연속 자리표시(`impact {1}{2}{3}`)가 ", 외부" 조각을 삼킴 → 조각 단어 '외부'·'비가역' 카탈로그 추가 + vitest 1건 ② 대응 단계 기록(사용자가 입력한 메모)이 한국어 → `data-user` 표시(사용자 데이터 제외 규칙). 이의 상세·결정 메모도 같은 표시. 재점검(run-recheck.txt) 150쪽 위반 0 · 관문 8틀 29쪽 한글 0 · 46/46 PASS
- 전 경로 회차 첫 시도는 dev 서버 메모리 임계 재시작 중 `ERR_CONNECTION_RESET` 으로 중단 → 이동 재시도를 모든 Playwright 오류로 넓힘
- prod 회귀(PostgreSQL, prod-build → 0018 head → db-ping → 스모크, prod-smoke.txt): 원장 전체 검증 ok(1,126,614건·32초) · 성공 지표 12 · 표본 기본 꺼짐 · 보존 계획(만료 대상 없음) · 정책 privileged · **특권 사용자 로그인 → enrollRequired·등록 전 API 401** · 규칙 영어·판정 ruleDescriptionEn·사건 runbookTextEn · 내장 임대(PG 새 열) 발급·확인·회수 · 계약 218 · 웹 /login 200 → `make prod-stop` → `make local-all` 복귀
- 스모크 스크립트 자체 오류 3건(지표 응답 키, 시험 사용자 비밀번호, 중첩 `$( )` 따옴표)은 고친 뒤 다시 실행 — 제품 결함 아님
