#!/usr/bin/env bash
# 폐쇄망 미러 채우기 (Epic 61) — 반입 매체를 만드는 '인터넷 쪽' 단계. compose registry(127.0.0.1:${REGISTRY_PORT}) 에
# infra/mirror/images.txt 의 이미지(노드 아키텍처 한 가지 — 외부 이미지는 crane 고정 판으로 레지스트리 간 복사)와 헬름 차트(OCI)를 올린다. 폐쇄망 쪽 설치는 MIRROR=1 scripts/k8s_rehearsal.sh.
set -euo pipefail
REG=localhost:${REGISTRY_PORT:-5005}
NET=${MIRROR_NET:-aegis-mirror}
ARCH=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
CID=$(docker ps -q -f label=com.docker.compose.service=registry -f label=com.docker.compose.project=aegismesh-local)
docker network inspect "$NET" -f '{{range .Containers}}{{.Name}} {{end}}' | grep -q "$(docker inspect -f '{{.Name}}' "$CID" | tr -d /)" \
  || docker network connect --alias aegis-registry "$NET" "$CID"
CRANE=gcr.io/go-containerregistry/crane:v0.20.3
grep -v '^#' infra/mirror/images.txt | while read -r src dst; do
  [ -n "$src" ] || continue
  case "$src" in
    aegismesh-*)                                                        # 우리 이미지 = 방금 빌드한 단일 플랫폼 → 도커로 올림
      docker tag "$src" "$REG/$dst" && docker push -q "$REG/$dst" >/dev/null
      echo "pushed $dst ← local $src" ;;
    *)                                                                  # 외부 이미지 = 원 레지스트리 → 미러 직접 복사(노드 아키텍처만, 로컬 저장소 거치지 않음)
      docker run --rm --network "$NET" "$CRANE" copy --platform "linux/$ARCH" --insecure "$src" "aegis-registry:5000/$dst" >/dev/null 2>&1
      echo "copied $dst ← $src @ $(docker run --rm --network "$NET" "$CRANE" digest --insecure "aegis-registry:5000/$dst")" ;;
  esac
done
mkdir -p build/mirror
helm package deploy/helm/aegismesh -d build/mirror >/dev/null
CHART=$(ls -t build/mirror/aegismesh-*.tgz | head -1)
helm push "$CHART" "oci://$REG/charts" --plain-http 2>&1 | grep -E "Pushed|Digest" || true
curl -fsS "http://$REG/v2/_catalog" | python3 -c 'import json,sys; print("catalog", json.load(sys.stdin)["repositories"])'
