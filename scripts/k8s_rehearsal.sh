#!/usr/bin/env bash
# k3d 로컬 클러스터 설치 리허설 (NFR-C1, SCR-A02) — 로컬 이미지 import → helm install → 스모크 → 롤링 갱신 → 삭제.
# 실제 운영 배포가 아니다. 클러스터는 이 로컬 도커 안에만 생기고 끝나면 지운다(KEEP=1 이면 유지).
# MIRROR=1 (Epic 61) — 폐쇄망 설치: 이미지 import 대신 docker.io = 사내 미러(compose registry, make mirror-push), 원 레지스트리 경로 끔,
#   traefik·servicelb 끔(미러에 없는 이미지), 헬름 차트도 미러(OCI)에서.
set -euo pipefail
CLUSTER=${CLUSTER:-aegismesh-rehearsal}; NS=${NS:-aegismesh}; REL=${REL:-aegis}; PORT=${PORT:-18080}
CHART=deploy/helm/aegismesh
IMAGES=(aegismesh-api:prod aegismesh-web:prod postgres:17-alpine otel/opentelemetry-collector-contrib:0.162.0)
log() { printf '\n## %s\n' "$*"; }
cleanup() { [ -n "${PF:-}" ] && kill "$PF" 2>/dev/null || true; [ "${KEEP:-0}" = 1 ] || k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

REG=localhost:${REGISTRY_PORT:-5005}
EXTRA=(); CHART_REF=("$CHART")
if [ "${MIRROR:-0}" = 1 ]; then
  CLUSTER=${CLUSTER%-rehearsal}-airgap
  EXTRA=(--network "${MIRROR_NET:-aegis-mirror}" --registry-config infra/mirror/registries.yaml
         --k3s-arg "--disable-default-registry-endpoint@server:0" --k3s-arg "--disable=traefik@server:0" --k3s-arg "--disable=servicelb@server:0")
  VER=$(python3 -c "import re; print(re.search(r'^version:\s*(\S+)', open('$CHART/Chart.yaml').read(), re.M).group(1))")
  CHART_REF=("oci://$REG/charts/aegismesh" --version "$VER" --plain-http)
  curl -fsS "http://$REG/v2/_catalog" >/dev/null || { echo "미러 없음 — make mirror-push 먼저"; exit 1; }
fi
log "클러스터 생성 ($CLUSTER, 로드밸런서 없음$( [ "${MIRROR:-0}" = 1 ] && echo ", 미러 전용"))"
k3d cluster list "$CLUSTER" >/dev/null 2>&1 || k3d cluster create "$CLUSTER" --no-lb --wait --timeout 180s "${EXTRA[@]}"
kubectl config use-context "k3d-$CLUSTER" >/dev/null
if [ "${MIRROR:-0}" = 1 ]; then
  log "미러 확인 — 원 레지스트리 경로 꺼짐, 노드 이미지는 아직 시스템 이미지뿐"
  docker exec "k3d-$CLUSTER-server-0" cat /etc/rancher/k3s/registries.yaml
  docker exec "k3d-$CLUSTER-server-0" crictl info 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print("containerd mirrors", list(((d.get("config") or {}).get("registry") or {}).get("mirrors", {}).keys()))' || true
fi
[ "${MIRROR:-0}" = 1 ] || log "로컬 이미지 반입 (레지스트리 pull 없음)"
# Docker Desktop containerd 저장소는 다중 아키텍처 인덱스를 통째로 내보내 노드 import 가 실패한다 → 노드 아키텍처만 저장해 ctr 로 넣는다
ARCH=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')
for img in $( [ "${MIRROR:-0}" = 1 ] || echo "${IMAGES[@]}" ); do
  docker save --platform "linux/$ARCH" "$img" | docker exec -i "k3d-$CLUSTER-server-0" ctr -n k8s.io images import - >/dev/null
  echo "imported $img (linux/$ARCH)"
done

log "헬름 설치 (비밀값은 이 리허설에서 생성 — 운영은 existingSecret)"
rnd() { python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())'; }
t0=$(date +%s)
helm upgrade --install "$REL" "${CHART_REF[@]}" -n "$NS" --create-namespace --wait --wait-for-jobs --timeout 10m \
  --set secrets.dbPassword="$(python3 -c 'import secrets; print(secrets.token_hex(16))')" \
  --set secrets.ledgerSigningKey="$(rnd)" --set secrets.svidSigningKey="$(rnd)" --set secrets.authSecret="$(rnd)" \
  --set config.extra.TENANCY_TEST_INTERVAL_SEC="86400"
echo "설치 소요 $(( $(date +%s) - t0 ))초"
kubectl -n "$NS" get pods -o wide
kubectl -n "$NS" get job "$REL-migrate" -o jsonpath='{.status.succeeded}{" migrate job succeeded\n"}'
if [ "${MIRROR:-0}" = 1 ]; then
  log "노드 이미지 출처 — 모두 docker.io 이름(= 사내 미러), 미러 접근 기록"
  docker exec "k3d-$CLUSTER-server-0" crictl images | tail -n +2 | awk '{print $1":"$2}'
  docker logs "$(docker ps -q -f label=com.docker.compose.service=registry -f label=com.docker.compose.project=aegismesh-local)" 2>&1 \
    | grep -oE 'GET /v2/[^ ]+/manifests/[^ "]+' | sort | uniq -c | sort -rn | head -12
fi

log "스모크"
kubectl -n "$NS" port-forward "svc/$REL-api" "$PORT:8000" >/dev/null 2>&1 & PF=$!
for i in $(seq 1 30); do curl -fsS "localhost:$PORT/health" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "localhost:$PORT/health"; echo
TOK=$(kubectl -n "$NS" exec "deploy/$REL-api" -- python -m app.admin bootstrap-token | grep -oE 'aegis-boot-[A-Za-z0-9_-]+')
PW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')
SESS=$(curl -fsS "localhost:$PORT/v1/auth/bootstrap" -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK\",\"username\":\"k8s.admin\",\"password\":\"$PW\",\"tenantId\":\"default\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
H="Authorization: Bearer $SESS"
curl -fsS -H "$H" "localhost:$PORT/v1/coverage" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("coverage", d["implemented"], "/", d["total"])'
curl -fsS -H "$H" -H 'content-type: application/json' "localhost:$PORT/v1/profiles/tool-agent:apply" -d '{"target":"k8s.example"}' >/dev/null
curl -fsS -H "$H" -H 'content-type: application/json' "localhost:$PORT/v1/judge:batch" \
  -d '{"gate":"tool","target":"k8s.example","request":{"tool":{"name":"transfer_funds","args":{"amount":5000}}}}' \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("judge:batch", d["verdict"], len(d["agents"]), "agents", d["latencyMs"], "ms")'
curl -fsS -H "$H" "localhost:$PORT/v1/evidence:verify" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("ledger verify", d["ok"], d["records"])'
curl -fsS -H "$H" "localhost:$PORT/v1/sandbox" | python3 -c 'import json,sys; d=json.load(sys.stdin); c=d["capabilities"]; print("sandbox", d["maxLevel"], "landlock", c.get("landlock"), "seccomp", len(c.get("seccomp") or []))'
curl -fsS -H "$H" -X POST "localhost:$PORT/v1/tenants:isolation-test" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("isolation", d["passed"], "/", d["total"], "rls", next(c["detail"] for c in d["checks"] if c["id"]=="rls"))'
curl -fsS -H "$H" "localhost:$PORT/v1/observability" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("otel", d["enabled"], d["endpoint"])'

kubectl -n "$NS" rollout status "deploy/$REL-worker" --timeout 120s
kubectl -n "$NS" get pods -l app.kubernetes.io/component=worker -o jsonpath='{range .items[*]}{.metadata.name}{" restarts="}{.status.containerStatuses[0].restartCount}{" ready="}{.status.containerStatuses[0].ready}{"\n"}{end}'
kubectl -n "$NS" logs "deploy/$REL-worker" --tail=50 | grep -E "스키마 대기|worker 시작|job " | head -5  || true   # 로그에 해당 줄이 없어도(빨리 시작) 리허설을 멈추지 않는다

log "롤링 갱신 (NFR-O2 — 설정 변경 → 무중단 교체)"
helm upgrade "$REL" "${CHART_REF[@]}" -n "$NS" --reuse-values --set config.evidenceRetentionDays=365 --wait --wait-for-jobs --timeout 5m >/dev/null
kubectl -n "$NS" rollout status "deploy/$REL-api" --timeout 120s
for i in $(seq 1 30); do curl -fsS "localhost:$PORT/health" >/dev/null 2>&1 && break; kill "$PF" 2>/dev/null || true
  kubectl -n "$NS" port-forward "svc/$REL-api" "$PORT:8000" >/dev/null 2>&1 & PF=$!; sleep 1; done
curl -fsS -H "$H" "localhost:$PORT/v1/data-protection" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("retention after upgrade", d["retention"]["default"])'
helm -n "$NS" history "$REL" | tail -2
log "완료 — 클러스터 $( [ "${KEEP:-0}" = 1 ] && echo 유지 || echo 삭제)"
