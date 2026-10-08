# 시험 결과 / Test Result — impl 52nd (Epic 52 백업 외부 복사)
- 일자: 2026-10-07 · 대상: prod 리허설(PostgreSQL, 원장 157만 건·백업 17 GB) + SeaweedFS 4.48 · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 5회: 버킷 생성 권한 / 평문 부가 포트 / gRPC 평문 / IAM 서명 키 / 구운 certs.py)
- 외부 복사: 기본 백업 4개·WAL 924개 → 객체 저장 18.2 GB(로컬 17 GB, 파일마다 KMS 봉투 암호화) · WAL 전환 → 외부 복사 **30 s**(상한 ≈ 2분)
- 객체 저장에는 평문 없음 — 로컬 WAL 에 평문으로 있는 표식 3종이 객체 저장 데이터 파일 150개에 **0건**
- **객체 저장 복사본만으로 복구 훈련**: 받기 133개·3.8 GB 를 5.1 s 에 복호화·검증 → 복원·WAL 재생 → 원장 1,576,860건 검증 OK · **RTO 93 s**
- 객체 저장은 S3(8333)·gRPC(18333) 모두 클라이언트 인증서 필수, 나머지는 컨테이너 안(127.0.0.1)만 · `make test` 436 passed

## 구현
- `app/offsite.py` — S3 SigV4(표준 라이브러리), 상호 TLS, 파일마다 새 DEK(KMS 포장)·4 MB 조각 AES-256-GCM(AAD = 키 + 조각 번호)·원문 sha256, 복사(완료 백업만, START_WAL 을 마지막에)·정리(DB_BACKUP_KEEP)·받기(최신 백업 + 그 경계 이후 WAL)·상태 · `app/kms.py` `new_data_key`·`open_data_key`
- compose prod `objstore`(SeaweedFS 4.48, `infra/objstore/start.sh`·`security.toml`, 볼륨 `objdata`) · `backup-ship`(api 이미지, uid 0 이지만 권한은 DAC_READ_SEARCH 만, 마운트 전부 읽기 전용) · `db-drill` 의 /backup 원천을 `DRILL_SOURCE_VOLUME` 으로 · 볼륨 `dboffsite`
- `scripts/certs.py` 말단 `objstore`(S3·gRPC 서버이자 내부 클라이언트) · `scripts/dr_drill.sh` `SOURCE=offsite` · Makefile `db-offsite`·`db-restore-drill SOURCE=` · env `S3_*`·`OFFSITE_INTERVAL_SEC` · `test/test_offsite.py` 3건

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 436 passed · test_offsite 3 |
| C02 | PASS | S3 인증서 없이 TLSV13_ALERT_CERTIFICATE_REQUIRED · 평문 HTTP 400 · api 인증서(서명 없음) 403 · gRPC 18333 인증서 없이 거부·있으면 성립 · 9333·8888·8080 접근 불가 · 열린 포트 `:8333`·`:18333` 뿐(logs/c02-listeners.txt) |
| C03 | PASS | 첫 복사 735개 · 상태 remoteBackups 4·remoteWal 924·18,231,585,531 B · 로컬 백업 4·WAL 926(복사 직후 새로 생긴 2개) |
| C04 | PASS | chatbot-baseline 139→0 · load.test 135→0 · svc.loadtest 169→0 (로컬 WAL 포함 파일 → 객체 저장 데이터 파일) |
| C05 | PASS | 세그먼트 …04000000DD 보관 0 s · 외부 복사 30 s |
| C06 | PASS | `{"backup": "20261007T113213Z", "objects": 133, "bytes": 3804449386, "sec": 5.1}` · 풀기 25 s · 재생 6.3 s · 검증 51 s · RTO 93 s · 원장 seq 1582274 기록 |

## 회차 / Rounds
- round 1: 버킷 만들기 403 AccessDenied — 자격 증명에 Admin 없음 → 권한을 백업 버킷 하나로 한정해 부여
- round 2: Iceberg REST(8181)·Lance(9101)가 0.0.0.0 평문 → `-s3.port.iceberg=0 -s3.port.lance=0`
- round 3: S3 gRPC 18333 이 0.0.0.0 평문 → `security.toml` 로 gRPC 상호 TLS. 처음엔 회전이 옛 certs.py(api 이미지에 구워짐)로 돌아 SAN·용도 미반영 → 이미지 재빌드 후 회전
- round 4: gRPC TLS 를 켜자 S3 IAM "no signing key found for STS service" → 기동마다 무작위 `jwt.filer_signing` 키
- round 5: 통과. compose 가 `dboffsite` 볼륨을 직접 만들지 않았다는 경고만(동작 영향 없음)

## 남은 것 / Notes
- 리허설의 객체 저장은 같은 호스트다 — 운영은 다른 호스트·사이트(또는 외부 S3)로 `S3_ENDPOINT` 를 돌린다.
- builtin KMS 키 고리는 appdata 볼륨에 있어 호스트를 통째로 잃으면 외부 복사본도 못 연다 → 운영은 영속 OpenBao(외부 KMS) 또는 키 고리 별도 보관.
