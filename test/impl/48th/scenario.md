# 48th — 내부 상호 TLS (Epic 48 · NFR-D3)

근거: 원본 PRD NFR-D3 "모든 내부 구간 상호 TLS", D9-03 권고(상호 TLS 기본화·인증서 자동 발급·회전), PRD.md §5 보안·데이터.
환경: prod 리허설(로컬 Docker). 인증서는 실행 시 만든 내부 CA(볼륨 `tls`, 비커밋). 키·토큰 값은 출력하지 않는다.
구간: web→api · api·worker→db · db-standby·db-backup→db(복제) · api·worker→otel-collector. local 은 평문 개발 모드(대상 아님).

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (`test/test_tls.py` 7건: 발급·소유자·용도·갱신·회전·클라이언트 묶음·상호 핸드셰이크·상태 API·구성) | P0 |
| C02 | 기동 | `make prod-build` | tls-init 이 CA·말단 5종 발급 후 종료(0), 전 서비스 healthy | P0 |
| C03 | api→db TLS | `GET /v1/observability/tls` · pg_stat_ssl | 이 연결 ssl true·TLSv1.3·clientDn CN=api, 원격 백엔드 전부 ssl | P0 |
| C04 | 복제 TLS | pg_stat_ssl(walsender) · 동기 등록 | walsender ssl true·CN=replicator, standby1 sync | P0 |
| C05 | 평문·무인증서 거부 (DB) | 같은 네트워크의 컨테이너에서 psql sslmode=disable / sslmode=require(인증서 없음) | 둘 다 거부 | P0 |
| C06 | 평문·무인증서 거부 (API) | 호스트 curl http / https(인증서 없음) / https(+operator 묶음) | 실패 / 거부 / 200 | P0 |
| C07 | web→api 상호 TLS | 콘솔 페이지 요청 · api 접근 로그 | 콘솔이 API 응답으로 화면을 그림(web 컨테이너 출발) | P0 |
| C08 | OTLP 상호 TLS | 수집기에 인증서 없이 / api 내보내기 통계 | 거부 / 전송 성공 증가·실패 0 | P0 |
| C09 | 무중단 회전 | 부하 중 `make certs-rotate ENV=prod` | 말단 일련번호 변경(CA 유지), 부하 오류 0, 새 인증서로 api·PG 응답, 콘솔·내보내기 계속 | P0 |
| C10 | 재해 복구 회귀 | `make db-restore-drill ENV=prod` | 복구 서버(db-drill)도 TLS(verify-full) 로 검증 통과 | P1 |
| C11 | 성능 | `make loadtest ENV=prod` | 오류 0, 관문 실행 p95 예산 이내(47th 대비 처리량 기록) | P1 |
| C12 | 외부 도구 묶음 | `make certs-client ENV=prod NAME=operator` | infra/tls/clients/operator (키 0600, .gitignore) | P1 |
| C13 | 콘솔 | `/observability` ko·en (local) | TLS 카드, en 한글 0, 접근성 위반 0 | P1 |
