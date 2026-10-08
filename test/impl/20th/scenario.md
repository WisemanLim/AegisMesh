# 20차 시나리오 — Epic 20 헬름 차트·k8s 리허설·단일 파일 CLI

근거: NFR-C1(쿠버네티스·도커 컴포즈·단일 호스트), PRD 배포 형태(컨테이너 이미지 + 헬름 차트 + 단일 바이너리 CLI), NFR-O2(무중단 갱신),
SCR-A01(설치 안내·사전 점검), A02(헬름 마법사), A03(컴포즈), A04(CLI·M1). 결정(4차): k3d 로컬 클러스터 실제 설치 리허설.

| id | 목적 | 입력 | 기대 | 우선 |
|---|---|---|---|---|
| T20-01 | 차트 정적 검증 | `make helm-lint` | lint OK, template OK, 비밀 누락 시 설치 거부(CHANGE_ME 금지) | P0 |
| T20-02 | k3d 설치 리허설 | `make k8s-rehearsal` | 로컬 이미지 반입 → helm install(--wait-for-jobs) → 마이그레이션 Job 성공, 파드 전부 Ready | P0 |
| T20-03 | 클러스터 안 스모크 | 부트스트랩·판정·원장·샌드박스·RLS·OTel | 커버리지 80/80, 관문 판정, 원장 검증, L1(Landlock·seccomp), 격리 7/7(RLS aegis_app), 수집기 | P0 |
| T20-04 | 무중단 갱신 | `helm upgrade` 설정 변경 | 롤링 교체 완료·설정 반영(보존 365) | P1 |
| T20-05 | 단일 파일 CLI | `make cli` → 파이썬 없는 debian(--network none) | list·run·eval·coverage·verify-bundle·airgap verify·keygen·serve | P0 |
| T20-06 | 콘솔 설치 화면 | /install · /install/helm · /compose · /cli | 사전 점검 실측 8/8, 헬름 값 생성 → helm template 렌더 성공 | P1 |
| T20-07 | 회귀 | make test·test-web·coverage·gen_otel_config --check | 통과 | P0 |
