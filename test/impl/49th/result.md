# 시험 결과 / Test Result — impl 49th (Epic 49 저장 암호화, NFR-D2)
- 일자: 2026-10-07 · 대상: local + OpenBao 2.4.1 운영형(raft, transit) · prod 리허설(PostgreSQL 17, 원장 134만·발견 108만 행) · 커밋: —

## 요약 / Summary
- 전체 12, 통과 12, 실패 0 → 최종 **PASS** (재시도 3회: 스크립트 시드 가정 2건 / 상태·재암호화가 108만 행에서 무거움)
- 봉투 암호화: 값마다 AES-256-GCM(DEK), DEK 는 KMS 의 KEK 로 포장해 값과 함께 저장(`aegis1.<포장 DEK>.<암호문>`) — DEK 표가 없어 추가 전용 원장과 충돌 없음, JSON 열은 `{"_enc": …}` 라 스키마 변경 없음
- KMS 위임: OpenBao transit(`aegis-kek`) — 브로커 토큰은 encrypt·decrypt 만(회전·키 조회 403), 감사 로그의 plaintext 필드 전부 HMAC. 봉인 중 새 프로세스는 `KmsError`(실패 시 닫힘), 해제 뒤 정상
- 덤프·백업 평문 0: prod 에 카나리를 대상 열 전부(원장·정책·발견·승인 요약·결정 사유·골든 표본·OTP 비밀)에 기록 → `pg_dump` 2.8 GB·보관 WAL 145개·기본 백업(base·pg_wal) 모두 **0건**
- 재암호화: `make kms-rewrap ENV=prod ROTATE=1` 2분 44초 — 발견 1,079,605·승인 4,837 등 전부 `builtin:v2`, 키 파일 3종 재포장, 발견·승인 덤프의 평문 `"ruleId"` 2,399,198 → **0**
- `make test` 423 passed · `make test-web` 15 passed + tsc · `/observability` ko·en 접근성 위반 0

## 구현
- `app/kms.py` — builtin(데이터 디렉터리 키 고리, 버전별 KEK, 0600·비커밋) / openbao(transit) 포장·해제, 프로세스 DEK(KMS_DEK_TTL_SEC 1시간), 해제 캐시, `EncryptedJSON`·`EncryptedText` 열 타입, `secret_file`(서명 키·세션 비밀 파일, 옛 평문은 처음 읽을 때 포장), `status`(표본 1000행 + 전체 건수, `--full` 정확 집계), `rotate_builtin`, `rewrap`(기본 키 순 묶음 UPDATE) · CLI `python -m app.kms status|rotate|rewrap`
- 암호화 열: `evidence.body`·`policies.body`·`profiles.spec`·`findings.body`·`approvals.summary`·`approval_decisions.reason`·`traffic_samples.request`·`golden_samples.request`·`users.totp_secret` / 파일: 원장·SVID 서명 키, 세션 서명 비밀
- 익명 행위 집계(거버넌스 SQL)는 `{"_enc", "by": "anonymous"}` 상수 표식으로 유지 · OTP 는 옛 봉인 형식도 읽음(`mfa._secret_of`)
- `scripts/bao_setup.py` transit 엔진·`aegis-kek` 생성, 브로커 정책 encrypt·decrypt, `rotate-kek` · Makefile `kms-rewrap [ENV=] [ROTATE=1]`·`bao-rotate-kek [MODE=server]` · `GET /v1/observability/kms` · 콘솔 `/observability` 저장 암호화 카드
- env `KMS_BACKEND`·`KMS_TRANSIT_KEY`(local·prod·example) · `test/conftest.py` 키 고리·비밀 파일을 임시 경로로(개발 볼륨 파일을 시험 키로 포장하지 않게) · `test/test_kms.py` 9건

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 423 passed · test_kms 9 (봉인·AAD·변조 / 원장 본문 암호화·체인 검증·내보내기 / 익명 집계 / 옛 평문·rewrap / builtin 회전·키 파일 재포장 / OTP 새·옛 형식 / 비밀 파일 / transit 가짜·백엔드 전환·DEK 캐시 / DB 파일 평문 0) |
| C02 | PASS | 일회용 DB(KMS_BACKEND=openbao): 대상 열 전부 `openbao:v1` · 키 파일 3종 `vault:` 포장 · 원장 검증 OK · DB 파일 카나리 0 |
| C03 | PASS | `rotate-kek` → v2 · 새 기록 `openbao:v2` · 옛 v1 원장 기록 읽힘 · rewrap 뒤 수정 가능 표 전부 v2 · 원장 검증 OK |
| C04 | PASS | 브로커 토큰: `transit/keys/aegis-kek/rotate` 403 · `transit/keys/aegis-kek` 403 |
| C05 | PASS | 봉인 중 새 프로세스 "KMS(OpenBao transit) 해제 실패 — Vault is sealed" · 해제 뒤 read [True, True] |
| C06 | PASS | 감사 로그 transit encrypt 7·decrypt 2·rotate 2(1건은 브로커 거부) · plaintext 필드 요청 7·응답 2 모두 `hmac-sha256:` |
| C07 | PASS | prod 기동 — 옛 평문 기록 그대로 읽힘, 새 원장 기록 암호화, 세션·SVID 키 파일 즉시 포장(원장 키는 다음 사용 때), 원장 1,340,975건 검증 OK 36.6 s |
| C08 | PASS | 카나리 ORM 읽기 True×3 · pg_dump 2,812 MB 카나리 0·OTP 표식 0 (대조: 암호화 전 발견 본문 평문 2,399,198곳) · WAL 145개 0 · 기본 백업 20261007T054522Z base·pg_wal 0 |
| C09 | PASS | ROTATE=1 → builtin KEK v2 · rewrap 2:44 · 표 전부 builtin:v2 · 키 파일 ✓✓✓ · 발견·승인 덤프 `"ruleId"` 0 · 원장 1,340,978건 검증 OK 42.1 s · 발견 본문 저장 크기 ×1.51(평균 900 → 1,362 B) |
| C10 | PASS | 226.5 rps 오류 0 · 관문 실행 p95 14.3/11.7/15.7 ms(예산 80/20/150) — 48th 261.5 rps 와 차이는 같은 VM 잡음 범위(47th 166~252) |
| C11 | PASS | 복구 훈련 1,383,206건 검증·RTO 138 s(재암호화로 늘어난 WAL 재생 90 s) — 키 고리는 appdata(DB 백업과 분리) |
| C12 | PASS | prod 카드 "KMS builtin · KEK v2 · 최근 증적 1000/1000 · findings.body 1000/1000 (builtin:v2) · 키 파일 ✓✓✓" · local ko·en 위반 0, en 한글은 기존 마스킹 예시(textarea)뿐 |

## 회차 / Rounds
- round 1: 운영형 bao-server 컨테이너가 지워진 옛 네트워크를 참조("network … not found") → 컨테이너만 재생성(raft 볼륨 유지). 그 사이 api 는 브로커 토큰 없음 → "KMS 포장 실패"(실패 시 닫힘 확인)
- round 2: E2E 스크립트가 시드에 사용자가 있다고 가정·역할 이름·서비스 계정 비밀번호 규칙 → 서비스 계정으로
- round 3: 회전 뒤 키 파일은 옛 KEK 포장 그대로 → `rewrap` 이 키 파일도 재포장(단위 시험 추가)
- round 4: prod 발견 108만 행 — `status` 가 전 행을 읽고 `rewrap` 이 ORM 단건 갱신 → 상태는 표본 1000행 + 건수(정확 집계는 `--full`), rewrap 은 기본 키 순 1000행 묶음 executemany(2:44)

## 남은 것 / Notes
- 원장은 추가 전용 — 암호화 전 기록(134만 건)은 평문으로 남고 보존기한 삭제(retention)로만 사라진다. 그 기록이 남아 있는 동안 옛 KEK 버전도 지우면 안 된다.
- builtin 키 고리는 appdata 볼륨(DB·백업과 분리)에 있다 — 함께 백업하지 않으면 복원한 DB 를 열 수 없다. 운영은 영속 OpenBao(transit, raft 스냅숏)를 쓴다. dev OpenBao 는 재기동 때 키를 잃으므로 KMS 로 쓰지 않는다.
- 재암호화 뒤 PostgreSQL 은 갱신된 행만큼 죽은 튜플이 남는다(findings 3.2 GB) — autovacuum 또는 `VACUUM (ANALYZE) findings`.
- 보안 검사로 실행하지 못한 것: 컨테이너 안 `sh -c … rm` 형태 명령 2건(임시 파일 삭제) — 임시 파일을 쓰지 않는 방식으로 바꿔 진행했다.
