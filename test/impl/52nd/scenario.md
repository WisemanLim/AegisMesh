# 52nd — 백업 외부 복사 (Epic 52 · NFR-A5 · 의존성 "객체 저장 SeaweedFS")

근거: NFR-A5(RTO 30분·RPO 5분), 47th 한계(백업이 같은 호스트 볼륨), PRD 의존성 "객체 저장(MinIO 대신 SeaweedFS)", NFR-D2·D3(저장·전송 암호화).

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (test_offsite: 8 MB 왕복·평문 없음·SigV4 머리·빈 파일·변조·옮김 탐지·복사·정리·복원) | P0 |
| C02 | 객체 저장 상호 TLS | 인증서 없이·평문·api 인증서로 S3·gRPC 접속, 내부 포트 | S3·gRPC 모두 인증서 없으면 거부, master·volume·filer 는 컨테이너 밖에서 접근 불가 | P0 |
| C03 | 외부 복사 | backup-ship 주기 복사 · `make db-offsite ENV=prod` | 로컬 기본 백업·WAL 이 원격에 같은 수, 완료된 백업만 | P0 |
| C04 | 저장 평문 0 | 로컬 WAL 에 평문으로 있는 표식 3종 | 객체 저장 데이터 파일에 0건 | P0 |
| C05 | 호스트 상실 RPO | WAL 전환 → 외부 복사까지 | ≤ archive_timeout + OFFSITE_INTERVAL_SEC(≤ 2분, 목표 5분) | P0 |
| C06 | 객체 저장만으로 복구 | `make db-restore-drill ENV=prod SOURCE=offsite` | 받기·복호화·검증 → 복원·재생 → 원장 전체 검증 OK, RTO ≤ 1800 s | P0 |
