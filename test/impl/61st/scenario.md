# 61st — 폐쇄망 레지스트리 미러 (Epic 61 · 폐쇄망 NFR · Harbor 대체)

근거: k3d 리허설(21st)은 노드에 이미지를 직접 import — 실제 폐쇄망은 사내 레지스트리에서 받는다. 헬름 차트도 로컬 경로였다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 레지스트리 | compose `registry`(distribution 3.0.0, 프로파일 mirror) | 127.0.0.1:5005, 볼륨 regdata | P0 |
| C02 | 미러 채우기 | `make mirror-push` | 시스템 이미지·AegisMesh·의존 이미지(노드 아키텍처, digest 고정)·헬름 차트 OCI | P0 |
| C03 | 미러 전용 설치 | `make k8s-mirror-rehearsal` | docker.io = 사내 미러, 원 레지스트리 경로 끔(`--disable-default-registry-endpoint`), 차트 = OCI 미러 → 설치·스모크·롤링 갱신 통과 | P0 |
| C04 | 새지 않음 | 미러에 없는 이미지 | 원 레지스트리로 가지 않고 NotFound(ImagePullBackOff) | P0 |
