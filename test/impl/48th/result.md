# 시험 결과 / Test Result — impl 48th (Epic 48 내부 상호 TLS, NFR-D3)
- 일자: 2026-10-07 · 대상: prod 리허설(로컬 Docker, PostgreSQL 17.10 주·대기, OTel 수집기 0.162.0) + local · 커밋: —

## 요약 / Summary
- 전체 13, 통과 13, 실패 0 → 최종 **PASS** (재시도 3회: pg_stat_ssl 자기 행 숨김 / psycopg SSL 속성 없음 / 부하 클라이언트 keep-alive 처리)
- 구간 4개 모두 상호 TLS: web→api(uvicorn CERT_REQUIRED) · api·worker→db(verify-full + CN=api 인증서) · 대기·백업→db(TLSv1.3, CN=replicator, verify-full) · api·worker→수집기(client_ca_file)
- 거부 확인: DB 평문 "no pg_hba.conf entry … no encryption" · DB 인증서 없음 "connection requires a valid client certificate" · API 평문·인증서 없음 연결 끊김 · 수집기 인증서 없음 "tlsv13 alert certificate required" · 수집기 평문 400
- 무중단 회전: 부하 45 s(11,766건) 중 `make certs-rotate ENV=prod` → **오류 0**, api·db·db-standby 일련번호 즉시 교체, 수집기 30 s 안에 교체, 콘솔·OTLP 계속. 처리량 261.5 rps(47th 평문 217~252 rps 와 차이 없음)
- `make test` 414 passed · `make test-web` 15 passed + tsc · `/observability` ko·en 접근성 위반 0

## 구현
- `scripts/certs.py` — 내부 CA(ECDSA P-256, 5년) + 말단 5종(db·replicator·api·web·otel, 90일): ensure(없으면 발급·만료 30일 전 재발급) · rotate · client NAME. 키는 서비스 실행 사용자 소유 0600, 원자 교체
- `docker-compose.prod.yml` — `tls-init`(일회성, 다른 서비스가 완료를 기다림) · 볼륨 `tls`(비커밋) 하위 경로를 서비스별 /tls 에 읽기 전용 · api uvicorn `--ssl-*`·`--ssl-cert-reqs 2`·TLS 헬스 검사 · web `API_URL=https://api:8000`·`API_TLS_DIR` · api·worker `PGSSL*`·`OTEL_EXPORTER_OTLP_*CERTIFICATE` · db·standby·drill `ssl=on` · 수집기 두 번째 `--config`
- `infra/postgres/pg_hba.conf` — 원격은 hostssl 만(복제 verify-full, 나머지 verify-ca) + SCRAM · `infra/otel/tls.yaml`(client_ca_file·reload_interval 30s)
- `app/tls.py`(client_context·status) · `GET /v1/observability/tls` · 콘솔 `/observability` TLS 카드 · `apps/web/lib/api.ts` `apiFetch`(Node https + 클라이언트 인증서, mtime 바뀌면 다음 연결부터 새 인증서) — prefs·logout·reports/export 라우트도 사용
- `scripts/loadtest.py` — https 면 상호 TLS, 응답 전에 닫힌 재사용 연결은 새 연결로 1회 재전송(재연결 수 보고)
- Makefile `certs-rotate`·`certs-client` · env `TLS_DIR`(local 빈 값, prod /tls) · prod `OTEL_ENDPOINT=https://…` · `.gitignore` `infra/tls/`
- `test/test_tls.py` 7건 · `app/core/config.py` openbao_token 주석 위치(7차 실행 때 잘못 붙인 것) 바로잡음

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 414 passed · test_tls 7 |
| C02 | PASS | tls-init: CA 생성(2031-10-06 까지) · db·replicator·api·web·otel 발급 → Exited(0) · 전 서비스 healthy |
| C03 | PASS | 앱 관찰 db {ssl true, sslmode verify-full, clientCert true} · DB 관찰 client backend app TLSv1.3 CN=api ×3 (logs/c03-c08.txt, c03-tls-status.json) |
| C04 | PASS | walsender replicator TLSv1.3 CN=replicator · standby1 streaming/sync |
| C05 | PASS | sslmode=disable → no encryption 거부 · 인증서 없음 → valid client certificate 요구 거부 · 인증서 있으면 TLSv1.3 CN=replicator |
| C06 | PASS | http 평문 curl exit 52 · https 인증서 없음 exit 52 · operator 묶음 200 `{"status":"ok","env":"prod",…}` |
| C07 | PASS | 세션 쿠키로 `/overview`·`/observability` 200, 오류 배너 없음 · api 접근 로그에 web IP(192.168.16.7) 출발 `/v1/agents`·`/v1/auth/me` 등 200 · TLS 카드 "TLS verify-full" (logs/c07-web.txt) |
| C08 | PASS | 인증서 없이 수집기 TLSV13_ALERT_CERTIFICATE_REQUIRED · 평문 400 · api 인증서 200 · 내보내기 traces 26·metrics 5·logs 8 성공, 실패 0 |
| C09 | PASS | 회전 전 {api 22a0…, db 2f3f…, otel 23ba…} → 회전 35 s 뒤 {api 2681…, db·standby 62fb…, otel 14af…} · api 로그 "Received SIGHUP, restarting processes" · 부하 11,766건 오류 0·재연결 78 · 관문 실행 p95 11.5/9.9/12.7 ms(예산 80/20/150) |
| C10 | PASS | 복구 훈련(db-drill verify-full) 1,340,950건 검증·RTO 61 s · 장애 조치 훈련(TLS 재복제) RTO 39 s·원장 RPO 0, 재복제 walsender TLSv1.3 CN=replicator |
| C11 | PASS | 261.5 rps · p95 486 ms(동시 64, 같은 VM) — 47th 평문 217~252 rps 대비 저하 없음 |
| C12 | PASS | `make certs-client ENV=prod NAME=operator` → infra/tls/clients/operator (tls.key 0600, .gitignore `infra/tls/`) |
| C13 | PASS | local `/observability` ko·en axe 위반 0, en 한글은 기존 마스킹 예시 입력(textarea)뿐 |

## 회차 / Rounds
- round 1: `tls.status` NoResultFound — `pg_stat_ssl` 은 client_port 가 보이는 행만 내는데, SET ROLE aegis_app 뒤에는 세션 사용자(app)의 자기 행도 숨김 → 클라이언트(libpq) 쪽 관찰로 교체
- round 2: psycopg_binary PGconn 에 `ssl_attribute` 없음(`ssl_in_use` 만) → ssl·sslmode·클라이언트 인증서 유무 보고, 버전·CN 은 DB 쪽 관찰(시험 스크립트)로
- round 3: 부하 중 회전에서 부하 클라이언트가 `IndexError`(빈 상태 줄)로 죽고 메인 프로세스가 대기 — SIGHUP 으로 은퇴하는 작업 프로세스가 keep-alive 연결을 닫은 것. 서버 오류가 아니라 클라이언트가 닫힌 연결을 처리하지 못한 결함 → 응답 전에 닫힌 재사용 연결만 새 연결로 1회 재전송, 횟수 보고. 재실행 오류 0

## 남은 것 / Notes
- local 은 평문 개발 모드(대상 아님). K8s(헬름)는 이 구성을 쓰지 않는다 — 운영은 서비스 메시(mTLS)·cert-manager 로 같은 구간을 덮는다.
- 외부 클라이언트(SDK·ingress)도 prod API 에는 클라이언트 인증서가 필요하다 → `make certs-client ENV=prod NAME=<이름>`.
- `scripts/loadtest.py` 의 기존 lint 2건(F841 `now`, RUF046)은 손대지 않음.
