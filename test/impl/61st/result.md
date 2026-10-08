# 시험 결과 / Test Result — impl 61st (Epic 61 폐쇄망 레지스트리 미러)
- 일자: 2026-10-08 · 대상: compose registry 3.0.0 + k3d 5.9.0(k3s v1.35.5-k3s1) · 커밋: —

## 요약 / Summary
- 전체 4, 통과 4, 실패 0 → 최종 **PASS** (재시도 5회: 다중 플랫폼 색인 변형 / 로컬 저장소 내용 없음 → crane / 미러 목록 busybox / 리허설 스크립트 pipefail)
- 미러: 이미지 9개(k3s 시스템 5·postgres·otel·aegismesh-api·web, 노드 아키텍처 하나·digest 고정) + 헬름 차트 OCI `charts/aegismesh:0.1.0`
- **미러만으로 설치**: k3s 레지스트리 설정 docker.io → `http://aegis-registry:5000`, 원 레지스트리 경로 끔 · 차트도 `oci://localhost:5005/charts/aegismesh` → 설치 43 s · coverage 80/80 · judge:batch · 원장 검증 · 격리 7/7 · 롤링 갱신(보존 365) → 클러스터 삭제, 전체 1:15
- **새지 않음**: 미러에 없던 local-path 볼륨 도우미(busybox)는 docker.io 로 가지 않고 `NotFound`(ImagePullBackOff) — 미러에 넣자 재시도로 회복

## 구현
- compose local 프로파일 `mirror` `registry`(127.0.0.1:${REGISTRY_PORT:-5005}, 볼륨 regdata) · `infra/mirror/images.txt`(이 k3s 판의 시스템 이미지 + 차트 이미지) · `infra/mirror/registries.yaml`
- `scripts/mirror_push.sh` — 외부 이미지는 crane v0.20.3(고정 판)으로 원 레지스트리 → 미러 직접 복사(노드 아키텍처), AegisMesh 이미지는 docker push, 헬름 차트 OCI push · 미러 네트워크 `aegis-mirror`(레지스트리 별칭 aegis-registry)
- `scripts/k8s_rehearsal.sh` `MIRROR=1` — 미러 네트워크·레지스트리 설정·원 경로 끔·traefik·servicelb 끔·OCI 차트, 노드 이미지·미러 접근 기록 출력 · 로그 grep 무일치가 리허설을 멈추던 결함 보정 · Makefile `mirror-push`·`k8s-mirror-rehearsal`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | c02-mirror-push.txt registry up |
| C02 | PASS | c02-mirror-push.txt — copied ×6(+busybox) · pushed ×2 · `Pushed: localhost:5005/charts/aegismesh:0.1.0` · catalog |
| C03 | PASS | c03-mirror-rehearsal-r3.txt — registries.yaml · 노드 이미지 9개 모두 docker.io 이름(= 미러) · 미러 접근 기록(manifests ?ns=docker.io) · 스모크 · exit 0 |
| C04 | PASS | c04-missing-image.txt `Failed to pull image "rancher/mirrored-library-busybox:1.37.0": rpc error: code = NotFound …` |

## 회차 / Rounds
- round 1: metrics-server 는 플랫폼 변형(arm64/v8)이라 `docker push --platform linux/arm64` 불일치
- round 2: 변형까지 맞춰도 Docker Desktop containerd 저장소가 `content digest … not found`(메모리의 k3d 반입 문제와 같은 계열) → 외부 이미지는 로컬 저장소를 거치지 않고 crane 으로 레지스트리 간 복사
- round 3: 미러 목록에 local-path 볼륨 도우미 busybox 누락 → 설치 중 NotFound(새지 않음 확인) → 목록 추가
- round 4: 리허설 스크립트가 worker 로그 grep 무일치로 `pipefail` 종료(기존 결함) → `|| true`
- round 5: 깨끗한 재실행 통과

## 남은 것 / Notes
- 레지스트리는 리허설용 평문 HTTP·인증 없음 — 운영은 TLS·인증(Harbor 등)·서명 검증(cosign) 레지스트리를 같은 미러 주소로.
- 미러 채우기(`make mirror-push`)는 반입 매체를 만드는 인터넷 쪽 단계, 폐쇄망 쪽은 `k8s-mirror-rehearsal` 만.
