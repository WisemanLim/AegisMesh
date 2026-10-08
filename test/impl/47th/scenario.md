# 47th — 백업·복구·동기 복제 (Epic 47 · NFR-A5)

근거: PRD.md §5 가용성 "RTO 30분 / RPO 5분(원장 0)", 원본 PRD NFR-A5 "증적 원장은 RPO 0 을 목표로 동기 복제", 8차 확인 질문(원장 RPO 0 = PG 동기 복제).
환경: prod 리허설(로컬 Docker, PostgreSQL 17, 원장 약 110만 건 · DB 4 GB). 비밀 값은 `.env.prod` placeholder, 출력하지 않는다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (`test/test_dr.py` 3건 포함) | P0 |
| C02 | prod 기동 | `make prod-build` → `db-migrate ENV=prod`(0019) | db·db-standby·db-backup healthy, 대기 서버 첫 복제, 동기 등록 로그 | P0 |
| C03 | 복제·보관 상태 | `GET /v1/observability/dr` | role primary · standby1 streaming/sync · ledgerRpo0 true · WAL 보관 실패 0 · archive_timeout 60 s | P0 |
| C04 | 원장만 동기 | 원장 쓰기 트랜잭션 vs 일반 트랜잭션의 `synchronous_commit` | 원장 = on, 일반 = local(주 서버 기본값) | P0 |
| C05 | 기본 백업 | `make db-backup ENV=prod` | base.tar.gz + pg_wal.tar.gz, START_WAL 경계, 목록·보관 WAL 개수 | P0 |
| C06 | 복구 훈련 (RTO) | `make db-restore-drill ENV=prod` | 전용 볼륨에 복원·WAL 재생·승격, 원장 전체 검증 OK, 기준점 머리 모두 존재, RTO ≤ 1800 s, 원장 kind=dr 기록, 훈련 볼륨 삭제, 운영 볼륨 무변경 | P0 |
| C07 | 일반 데이터 RPO | archive_timeout · 보관 경과 | 보관 경과 ≤ 300 s (RPO 5분), 설정 60 s | P0 |
| C08 | 동기 대기 동작 | 대기 서버 일시 정지 중 probe | 일반 커밋 즉시(ms), 원장 커밋은 대기 | P0 |
| C09 | 원장 RPO 0 · 장애 조치 | `make db-failover-drill ENV=prod CONFIRM=1` | 원장 20건 응답 직후 주 서버 정지 → 대기 서버 승격 → 마지막 응답 머리 존재·원장 검증 OK, RTO ≤ 1800 s, 복귀 후 대기 서버 재복제·동기 재등록 | P0 |
| C10 | 수동 강등 | `make db-sync ENV=prod MODE=off` → `on` | 대기 해제 즉시 반영(재시작 없음) → 재등록 | P1 |
| C11 | 안전장치 | `make db-backup`(ENV 없음) · `make db-failover-drill ENV=prod`(CONFIRM 없음) | 둘 다 실행 거부 | P1 |
| C12 | 콘솔 | `/observability` ko·en | 재해 복구 카드, en 한글 0 | P1 |
| C13 | 원장 무결성 | 훈련 전후 `GET /v1/evidence:verify` | ok, 훈련 기록만큼 증가 | P0 |
