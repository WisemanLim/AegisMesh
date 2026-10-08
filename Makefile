# aegismesh — python-fastapi (wise-vibe wds-scaffold 생성 / generated)
# 모드: local(SQLite) | prod(postgres) — 실행은 docker compose 전용. make help
PROJECT     := aegismesh
APP_SVC     := api
TEST        ?= pytest -q
MIGRATE     ?= alembic upgrade head
SEED        ?= python -m app.seed
SQLITE_PATH := /app/data/app.db
DB_ENGINE   := postgres
DB_PING     := pg_isready -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"
DB_SHELL    := psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"

## ===== wds 공통 타겟 / common targets (docker compose 전용 · 모드 = local | prod) =====
# local : docker-compose.yml + docker-compose.local.yml + .env.local  (SQLite, 소스 바인드/핫리로드, dev 스테이지)
# prod  : docker-compose.yml + docker-compose.prod.yml  + .env.prod   (DB_ENGINE 의 RDBMS 컨테이너, runtime 스테이지)
# compose/*.yml (scaffold --extras) 은 두 모드에 자동 포함된다.
ENV   ?= local
MODES := local prod
SVC   ?=
EXTRA_FILES := $(foreach f,$(sort $(wildcard compose/*.yml)),-f $(f))
DC_local := docker compose -p $(PROJECT)-local -f docker-compose.yml -f docker-compose.local.yml $(EXTRA_FILES) --env-file .env.local
DC_prod  := docker compose -p $(PROJECT)-prod  -f docker-compose.yml -f docker-compose.prod.yml  $(EXTRA_FILES) --env-file .env.prod
DC = $(DC_$(ENV))

.PHONY: help preflight test test-web contract-update coverage admin-token cli helm-lint k8s-rehearsal mirror-push k8s-mirror-rehearsal e2e-passkey e2e-a11y idp-up idp-down bao-up bao-unseal bao-down corpus-eval loadtest shell deploy db-ping db-shell db-migrate db-seed db-reset db-fresh db-backup db-restore-drill db-offsite db-failover-drill db-sync certs-rotate certs-client kms-rewrap bao-rotate-kek bao-hsm-up bao-hsm-status bao-hsm-down bao-cluster-up bao-cluster-unseal bao-cluster-status bao-cluster-down bus-up bus-down bus-tail garak-scan pins-refresh ledger-rewrap guard-up guard-down injguard-up injguard-down l2-up l2-down agw-up agw-down spire-up spire-down \
        $(foreach m,$(MODES),$(m)-all $(m)-build $(m)-logs $(m)-stop $(m)-restart $(m)-ps)

help:  ## 타겟 목록 / list targets
	@grep -hE '^[a-z][a-zA-Z%_-]*:.*## ' $(MAKEFILE_LIST) | sed -E 's/:[^#]*##/\t/' | awk -F'\t' '{printf "  %-14s %s\n", $$1, $$2}'
	@echo "  <mode>-all     [local|prod] 전체 스택 기동 (이미지 없으면 빌드)"
	@echo "  <mode>-build   [local|prod] 이미지 재빌드 후 기동"
	@echo "  <mode>-logs    [local|prod] 로그 추적 (SVC=<service>)"
	@echo "  <mode>-stop    [local|prod] 컨테이너 정리 (볼륨 유지)"
	@echo "  <mode>-restart [local|prod] 재기동 (SVC=<service>)"
	@echo "  <mode>-ps      [local|prod] 컨테이너 상태"
	@echo "  db-* 는 ENV=local|prod (기본 local). 예) make db-migrate ENV=prod"

preflight:  ## Docker·Compose v2·환경 파일 점검 / check docker, compose v2, env files
	@command -v docker >/dev/null 2>&1 || { echo "FAIL: Docker 미설치 / not installed"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "FAIL: docker compose v2 필요 / required"; exit 1; }
	@docker info >/dev/null 2>&1 || { echo "FAIL: Docker 데몬 미기동 / daemon not running"; exit 1; }
	@for f in .env.local .env.prod; do [ -f $$f ] || { echo "FAIL: $$f 없음 — cp .env.example $$f"; exit 1; }; done
	@grep -q 'CHANGE_ME' .env.prod && echo "WARN: .env.prod 에 CHANGE_ME placeholder — 실제 배포 전 Secret Manager 로 주입" || true
	@$(DC_local) config -q && $(DC_prod) config -q && echo "=== Preflight OK (DB_ENGINE local=sqlite, prod=$(DB_ENGINE)) ==="

## --- 모드별 수명주기 / lifecycle per mode ---
$(MODES:%=%-all): %-all:
	$(DC_$*) up -d
$(MODES:%=%-build): %-build:
	$(DC_$*) up -d --build
$(MODES:%=%-logs): %-logs:
	$(DC_$*) logs -f $(SVC)
$(MODES:%=%-stop): %-stop:
	$(DC_$*) down --remove-orphans
$(MODES:%=%-restart): %-restart:
	$(DC_$*) restart $(SVC)
$(MODES:%=%-ps): %-ps:
	$(DC_$*) ps

## --- 공통 / common ---
test:   ## local dev 컨테이너에서 테스트 실행
	$(DC_local) run --rm --no-deps --entrypoint sh $(APP_SVC) -c '$(TEST)'

test-web:  ## 콘솔(apps/web) 단위 시험 + 타입 검사 (local dev 컨테이너)
	$(DC_local) run --rm --no-deps --entrypoint sh web -c 'pnpm test && pnpm typecheck'

contract-update:  ## OpenAPI 계약 스냅샷 갱신 (의도한 API 변경 뒤 — test/contract/openapi.snapshot.json diff 를 리뷰)
	$(DC_local) run --rm --no-deps --entrypoint sh $(APP_SVC) -c 'python scripts/contract_snapshot.py'

coverage:  ## 도식 80 항목 누락 검증 (DP10·FR-P16) — 엄격 범위 누락 시 실패
	$(DC_local) run --rm --no-deps --entrypoint sh $(APP_SVC) -c 'python scripts/verify_coverage.py'
admin-token:  ## 첫 실행 부트스트랩 토큰 발급 (ENV=local|prod, RESET=1 = break-glass 재발급)
	$(DC) exec -T $(APP_SVC) python -m app.admin bootstrap-token $(if $(RESET),--reset,)
cli:  ## 단일 파일 CLI 빌드 → dist/aegis-linux-<arch> (PyInstaller, 리눅스용)
	docker build --target cli --output type=local,dest=dist/cli .
	mv -f dist/cli/aegis dist/aegis-linux-$$(uname -m) && rmdir dist/cli && ls -la dist/
helm-lint:  ## 헬름 차트 정적 검증 (lint + template)
	helm lint deploy/helm/aegismesh --set secrets.dbPassword=x --set secrets.ledgerSigningKey=x --set secrets.svidSigningKey=x --set secrets.authSecret=x
	helm template ci deploy/helm/aegismesh --set secrets.existingSecret=ci-secrets > /dev/null && echo "template OK"
k8s-rehearsal:  ## 로컬 k3d 클러스터에 헬름 설치 리허설 → 스모크 → 삭제 (KEEP=1 이면 유지)
	$(DC_prod) build api web
	bash scripts/k8s_rehearsal.sh
mirror-push:  ## 폐쇄망 미러 채우기(Epic 61) — compose registry 에 이미지(infra/mirror/images.txt, 노드 아키텍처)·헬름 차트(OCI) 올림
	$(DC_prod) build api web
	$(DC_local) --profile mirror up -d --wait registry
	bash scripts/mirror_push.sh
k8s-mirror-rehearsal:  ## 미러만으로 k3d 설치 리허설 — docker.io = 사내 미러, 원 레지스트리 경로 끔, 차트도 OCI 미러에서 (KEEP=1 이면 유지)
	MIRROR=1 bash scripts/k8s_rehearsal.sh
loadtest:  ## 판정 부하 측정 — 관문별 rps·p50/p95/p99 (ENV=prod 권장, DURATION·CONC·PROCS·MIX·LABEL·UNIQUE)
	$(DC) run --rm --no-deps $(APP_SVC) python scripts/loadtest.py --duration $(or $(DURATION),20) --conc $(or $(CONC),64) \
	  --procs $(or $(PROCS),4) $(if $(MIX),--mix $(MIX),) $(if $(UNIQUE),--unique,) --label "$(LABEL)"
e2e-passkey:  ## 패스키·DPoP E2E (Playwright + 가상 인증기, local) — OUT=test/impl/<N>/logs (e2e-credentials.env 필요)
	OUT=$(or $(OUT),test/impl/e2e) $(DC_local) --profile e2e run --rm e2e
e2e-a11y:  ## 접근성 점검 (axe-core WCAG 2.2 AA · 키보드, 전 경로 ko/en, local) — OUT=test/impl/<N>/logs [ONLY=/a,/b] (e2e-credentials.env 필요)
	OUT=$(or $(OUT),test/impl/e2e) E2E_ONLY=$(ONLY) $(DC_local) --profile e2e run --rm e2e python a11y_e2e.py
idp-up:  ## 조직 SSO 시험 IdP(Keycloak 26.3, local 전용) — 렐름·시험 사용자 생성(비커밋) 후 기동
	$(DC_local) run --rm --no-deps --entrypoint python $(APP_SVC) scripts/idp_realm.py
	$(DC_local) --profile idp up -d --wait keycloak
	@echo "Issuer http://localhost:$${IDP_PORT:-8080}/realms/aegis · Client aegismesh-console → /admin/sso"
idp-down:  ## 시험 IdP 중지
	$(DC_local) --profile idp stop keycloak
corpus-eval:  ## 공개 공격 코퍼스 실측(NFR-Q2) — 고정 커밋 이미지(infra/corpus) → corpora 볼륨 → 규칙 전용 vs 이중 판정(+ deep·model) × 직접·간접 재생(원장·/observability/slo) [VARIANTS=dual,model] [MODES=direct]
	$(DC_local) --profile corpus run --rm --build corpus
	$(DC_local) up -d --wait $(APP_SVC) worker
	$(DC_local) exec -T $(APP_SVC) python -m app.corpora $(VARIANTS) $(MODES)
bao-up:  ## OpenBao 시크릿 백엔드(local) — 정책·토큰 역할·브로커 토큰 구성 후 api·worker 를 OpenBao 임대로 재기동. MODE=server = 운영형 리허설(raft·봉인 해제·감사 장치)
ifeq ($(MODE),server)
	-$(DC_local) --profile bao stop bao
	$(DC_local) --profile bao-server up -d --wait bao-server
	$(DC_local) --profile bao-server run --rm --no-deps -e OPENBAO_SETUP_ADDR=http://bao-server:8200 --entrypoint python $(APP_SVC) scripts/bao_setup.py init
else
	-$(DC_local) --profile bao-server stop bao-server
	$(DC_local) run --rm --no-deps --entrypoint python $(APP_SVC) scripts/bao_setup.py keys
	$(DC_local) --profile bao up -d --wait bao
	$(DC_local) --profile bao run --rm --no-deps --entrypoint python $(APP_SVC) scripts/bao_setup.py configure
endif
	$(DC_local) up -d --wait $(APP_SVC) worker
bao-unseal:  ## 운영형 OpenBao 재기동 뒤 봉인 해제 (비커밋 infra/openbao/init.json 의 키 2개 — 운영은 키 보관자 분리·자동 봉인 해제)
	$(DC_local) --profile bao-server up -d --wait bao-server
	$(DC_local) --profile bao-server run --rm --no-deps -e OPENBAO_SETUP_ADDR=http://bao-server:8200 --entrypoint python $(APP_SVC) scripts/bao_setup.py unseal
bao-rotate-kek:  ## OpenBao transit 저장 암호화 KEK(aegis-kek) 회전 — 새 DEK 부터 새 버전, 옛 버전은 복호화 전용 (MODE=server = 운영형)
	$(DC_local) --profile $(if $(filter server,$(MODE)),bao-server,bao) run --rm --no-deps $(if $(filter server,$(MODE)),-e OPENBAO_SETUP_ADDR=http://bao-server:8200,) --entrypoint python $(APP_SVC) scripts/bao_setup.py rotate-kek
BAO_CLUSTER_RUN = $(DC_prod) run --rm --no-deps -v ./infra/openbao:/app/infra/openbao -e BAO_CACERT=/tls/ca.crt -e BAO_CLIENT_CERT=/tls/tls.crt \
	-e BAO_CLIENT_KEY=/tls/tls.key --entrypoint python $(APP_SVC) scripts/bao_setup.py
bao-cluster-up:  ## OpenBao 운영 마감 리허설(prod) — 봉인 해제기 + 3노드 raft(transit 자동 봉인 해제·상호 TLS 1.3) → api·worker 임대 백엔드 전환
	$(DC_prod) run --rm tls-init
	$(DC_prod) --profile bao-cluster up -d --wait bao-unsealer
	$(BAO_CLUSTER_RUN) unsealer
	$(DC_prod) --profile bao-cluster up -d --wait --force-recreate bao-1 bao-2 bao-3   # cluster.env(봉인 토큰)를 읽게 다시 만든다
	$(BAO_CLUSTER_RUN) cluster-init
	$(DC_prod) up -d --wait $(APP_SVC) worker
BAO_HSM_TOKEN = $(DC_prod) --profile bao-hsm run --rm --no-deps --user 100:1000 -e HSM_SO_PIN="$$(cat infra/openbao/hsm-so.pin)" --entrypoint /bin/sh bao-hsm /hsm/token.sh
bao-hsm-up:  ## OpenBao HSM 봉인 리허설(prod, Epic 68) — SoftHSM2 토큰·RSA-3072 비추출 봉인 키(OAEP) → pkcs11 자동 봉인 해제 노드 → 초기화(복구 키 3/2)·점검 비밀
	$(DC_prod) run --rm tls-init
	test -f infra/openbao/hsm.env || (umask 077; printf '# make bao-hsm-up 이 만든다(비커밋) — SoftHSM2 사용자 PIN\nBAO_HSM_PIN=%s\n' "$$(python3 -c 'import secrets; print(secrets.token_hex(16))')" > infra/openbao/hsm.env)
	test -f infra/openbao/hsm-so.pin || (umask 077; python3 -c 'import secrets; print(secrets.token_hex(16))' > infra/openbao/hsm-so.pin)
	$(DC_prod) --profile bao-hsm build bao-hsm
	$(BAO_HSM_TOKEN)
	$(DC_prod) --profile bao-hsm up -d --wait bao-hsm
	$(BAO_CLUSTER_RUN) hsm-init
bao-hsm-status:  ## HSM 봉인 노드 봉인 방식·상태 + 점검 비밀 읽기
	$(BAO_CLUSTER_RUN) hsm-status
bao-hsm-down:  ## HSM 봉인 노드 중지 (raft·토큰 볼륨은 남는다)
	-$(DC_prod) --profile bao-hsm stop bao-hsm
bao-cluster-unseal:  ## 봉인 해제기 재기동 뒤 Shamir 봉인 해제(비커밋 unsealer-init.json 키 2개) — 3노드는 스스로 다시 풀린다
	$(DC_prod) --profile bao-cluster up -d --wait bao-unsealer
	$(BAO_CLUSTER_RUN) unsealer
bao-cluster-status:  ## 노드별 봉인·리더·raft 투표자
	$(BAO_CLUSTER_RUN) cluster-status
bao-cluster-down:  ## 클러스터 중지 + api·worker 내장 브로커 복귀 (raft·봉인 해제기 볼륨은 남는다)
	rm -f infra/openbao/cluster-api.env
	-$(DC_prod) --profile bao-cluster stop bao-1 bao-2 bao-3 bao-unsealer
	$(DC_prod) up -d --wait $(APP_SVC) worker
GARAK_PROBES ?= promptinject.HijackHateHumans,promptinject.HijackKillHumans,promptinject.HijackLongPrompt,latentinjection.LatentInjectionReport,latentinjection.LatentInjectionResume,encoding.InjectBase64,encoding.InjectHex,encoding.InjectROT13,exploitation.JinjaTemplatePythonInjection,exploitation.SQLInjectionEcho,ansiescape.AnsiRaw,goodside.Tag
bus-up:  ## 발견 버스 켜기 [ENV=prod](Epic 60) — NATS JetStream + bus-relay(원장 커서 중계), api·worker 는 상태 조회용 BUS_URL(비커밋 infra/nats/api.env)
	$(if $(filter prod,$(ENV)),$(DC) run --rm tls-init,)
	printf '# make bus-up 이 만든다(비커밋) — 지우면 발견 버스 끔 (make bus-down)\nBUS_URL=%s\n%b' $(if $(filter prod,$(ENV)),tls://nats:4222 'BUS_CA_FILE=/tls/ca.crt\nBUS_CLIENT_CERT=/tls/tls.crt\nBUS_CLIENT_KEY=/tls/tls.key\n',nats://nats:4222 '') > infra/nats/api.env
	$(DC) --profile bus up -d --wait nats bus-relay
	$(DC) up -d --wait $(APP_SVC) worker
bus-down:  ## 발견 버스 끄기 [ENV=prod] — 스트림 볼륨(natsdata)은 남는다
	rm -f infra/nats/api.env
	-$(DC) --profile bus stop bus-relay nats
	$(DC) up -d --wait $(APP_SVC) worker
bus-tail:  ## 발견 버스 소비 예(SIEM) [ENV=prod] [DURABLE=siem] [MAX=20] — 지속 소비자로 받아 출력·확인
	$(DC) --profile bus run --rm --no-deps bus-relay python -m app.bus tail $(or $(DURABLE),siem) --max $(or $(MAX),20)
garak-scan:  ## 외부 레드팀 엔진 garak(Epic 59, local) — 같은 탐침을 무방비 모델과 AegisMesh 관문 뒤 모델에 → 원장(공격 성공률 비교) [OUT=test/impl/<N>/logs] [GARAK_PROBES=…]
	$(DC_local) run --rm --no-deps --entrypoint python $(APP_SVC) -m app.garak setup > infra/garak/target.env && chmod 600 infra/garak/target.env
	$(DC_local) --profile garak up -d --wait --force-recreate garak-target
	OUT=$(or $(OUT),test/impl/garak) $(DC_local) --profile garak run --rm garak --config /cfg/garak.yaml --target_type test.Repeat --probes $(GARAK_PROBES) --generations 1 --report_prefix baseline
	OUT=$(or $(OUT),test/impl/garak) $(DC_local) --profile garak run --rm garak --config /cfg/garak.yaml --target_type rest --generator_option_file /cfg/rest.json --probes $(GARAK_PROBES) --generations 1 --report_prefix guarded
	$(DC_local) run --rm --no-deps --entrypoint python $(APP_SVC) -m app.garak ingest $(or $(OUT),test/impl/garak)/guarded.report.jsonl $(or $(OUT),test/impl/garak)/baseline.report.jsonl
	-$(DC_local) --profile garak stop garak-target
pins-refresh:  ## 고정 판 갱신(Epic 58) — 이미지 빌드 안에서 DB-IP 최신 월·sha256, MDS3 다음 판을 정해 Dockerfile 전역 ARG 를 고친다(재빌드는 따로)
	docker build --target pins-out --build-arg PINS_AT=$$(date +%s) --output type=local,dest=build/pins .
	$(DC_local) run --rm --no-deps --entrypoint python $(APP_SVC) scripts/pins.py apply build/pins/pins.json
ledger-rewrap:  ## 원장 저장 재암호화 실행 [ENV=prod] [VACUUM=1] — 2인 승인으로 열린 창 안의 평문 기록을 묶음 암호화(Epic 57). VACUUM=1 = PG 파일 재작성(옛 행 판 제거)
	$(DC) run --rm --no-deps --entrypoint python $(APP_SVC) -m app.ledger_rewrap run
	$(if $(filter 1,$(VACUUM)),$(if $(filter prod,$(ENV)),$(DC) exec -T db sh -c '$(DB_SHELL) -c "VACUUM (FULL, ANALYZE) evidence"',),)
bao-down:  ## OpenBao 중지 + 내장 브로커로 복귀 (dev 임대는 사라지고, 운영형 임대는 raft 볼륨에 남는다)
	rm -f infra/openbao/api.env
	-$(DC_local) --profile bao stop bao
	-$(DC_local) --profile bao-server stop bao-server
	$(DC_local) up -d --wait $(APP_SVC) worker
shell:  ## 앱 컨테이너 셸 (ENV=local|prod)
	$(DC) exec $(APP_SVC) sh
deploy: ## prod 모드 롤아웃 (대상 호스트에서 실행 — 이미지 재빌드 + 재기동)
	@grep -q 'CHANGE_ME' .env.prod && { echo "FAIL: .env.prod 에 CHANGE_ME — 시크릿 주입 후 배포"; exit 1; } || true
	$(DC_prod) up -d --build --remove-orphans

## --- DB (ENV=local|prod, 기본 local) ---
db-ping:     ## DB 연결 확인 (local=SQLite 경로 · prod=DB 컨테이너 헬스)
ifeq ($(ENV),prod)
ifeq ($(DB_ENGINE),sqlite)
	$(DC_prod) run --rm --no-deps --entrypoint sh $(APP_SVC) -c 'mkdir -p $(dir $(SQLITE_PATH)) && echo "sqlite OK: $(SQLITE_PATH)"'
else
	$(DC_prod) exec -T db sh -c '$(DB_PING)' && echo "$(DB_ENGINE) OK"
endif
else
	$(DC_local) run --rm --no-deps --entrypoint sh $(APP_SVC) -c 'mkdir -p $(dir $(SQLITE_PATH)) && echo "sqlite OK: $(SQLITE_PATH)"'
endif
db-shell:    ## DB 클라이언트 접속 (prod RDBMS 전용)
	@[ "$(ENV)" = "prod" ] && [ "$(DB_ENGINE)" != "sqlite" ] || { echo "db-shell 은 ENV=prod + RDBMS 전용 (local SQLite: $(SQLITE_PATH))"; exit 1; }
	$(DC_prod) exec db sh -c '$(DB_SHELL)'
db-migrate:  ## 마이그레이션 적용 (MIGRATE 변수)
	$(DC) run --rm --entrypoint sh $(APP_SVC) -c '$(MIGRATE)'
db-seed:     ## 시드 적재 (SEED 변수)
	$(DC) run --rm --entrypoint sh $(APP_SVC) -c '$(SEED)'
db-reset:    ## [local 전용] SQLite 삭제 + 마이그레이션 — prod 거부
ifeq ($(ENV),prod)
	@echo "prod DB reset 금지 / refused"; exit 1
else
	$(DC_local) run --rm --no-deps --entrypoint sh $(APP_SVC) -c 'rm -f $(SQLITE_PATH)'
	$(MAKE) db-migrate ENV=local
endif
db-fresh: db-reset  ## [local 전용] db-reset + db-seed
	$(MAKE) db-seed ENV=local

## --- 재해 복구 (prod 전용, NFR-A5 — RTO 30분 · RPO 5분 · 원장 RPO 0) ---
PROD_ONLY = @[ "$(ENV)" = "prod" ] || { echo "$@ 은 ENV=prod 전용 (local = SQLite·평문 개발 모드)"; exit 1; }
db-backup:   ## [prod] 기본 백업 즉시 1회 + 목록 (pg_basebackup → 볼륨 dbbackup, 최근 DB_BACKUP_KEEP 개) — 주기 백업은 db-backup 서비스
	$(PROD_ONLY)
	$(DC_prod) exec -T db-backup sh /aegis-pg/backup.sh once
	$(DC_prod) exec -T db-backup sh /aegis-pg/backup.sh list
db-restore-drill:  ## [prod] 복구 훈련 — 최신 기본 백업 + 보관 WAL 을 전용 볼륨에 복원·승격 → 원장 검증·RTO 측정 (운영 볼륨 무변경, KEEP=1 유지, SOURCE=offsite = 객체 저장 복사본만으로)
	$(PROD_ONLY)
	SOURCE=$(or $(SOURCE),local) DC="$(DC_prod)" bash scripts/dr_drill.sh restore
db-offsite:  ## [prod] 백업 외부 복사 즉시 1회 + 상태 (objstore S3 상호 TLS, 파일마다 KMS 봉투 암호화 — 평소엔 backup-ship 이 OFFSITE_INTERVAL_SEC 마다)
	$(PROD_ONLY)
	$(DC_prod) exec -T backup-ship python -m app.offsite ship
	$(DC_prod) exec -T backup-ship python -m app.offsite status
db-failover-drill:  ## [prod] 장애 조치 훈련(CONFIRM=1) — 주 서버 일시 정지 → 대기 서버 승격·원장 RPO 0 확인 → 주 서버 복귀·대기 서버 재복제
	$(PROD_ONLY)
	@[ "$(CONFIRM)" = "1" ] || { echo "주 서버를 일시 정지하고 대기 서버를 승격한 뒤 다시 복제합니다 — CONFIRM=1 로 실행"; exit 1; }
	DC="$(DC_prod)" bash scripts/dr_drill.sh failover
db-sync:     ## [prod] 원장 동기 복제 MODE=on|off (대기 서버 장기 장애 때 off = 원장 커밋 대기 해제·RPO 0 해제, 복구 뒤 on)
	$(PROD_ONLY)
	$(DC_prod) exec -T db sh /aegis-pg/sync.sh $(or $(MODE),on)

## --- 워크로드 신원 SPIRE (Epic 53, 프로파일 spire) — 발급·키·회전은 SPIRE, AegisMesh 신원 목록은 등록 항목으로 동기화 ---
spire-up:    ## SPIRE 켜기 [ENV=prod] — server → 신뢰 번들·노드 join token(별칭 node/api) → infra/spire/api.env(IDENTITY_BACKEND=spire) → api·worker → agent(api PID 네임스페이스) → 등록 동기화
	$(DC) --profile spire up -d --wait spire-server
	$(DC) --profile spire exec -T spire-server /opt/spire/bin/spire-server bundle show -socketPath /run/spire/server/api.sock > infra/spire/bundle.pem
	printf '# make spire-up 이 만든다(비커밋) — 지우면 내장 발급자 (make spire-down)\nIDENTITY_BACKEND=spire\n' > infra/spire/api.env
	$(DC) up -d --wait $(APP_SVC) worker
	SPIRE_JOIN_TOKEN=$$($(DC) --profile spire exec -T spire-server /opt/spire/bin/spire-server token generate -socketPath /run/spire/server/api.sock -spiffeID spiffe://aegismesh.local/node/api -ttl 600 | awk '{print $$2}') \
	  $(DC) --profile spire up -d --wait --force-recreate spire-agent
	$(DC) exec -T $(APP_SVC) python -c "from app import db, identity; s = db.system_session(); print('sync', identity.sync(s)); s.commit()"
spire-down:  ## SPIRE 끄기 [ENV=prod] — 내장 발급자로 복귀(SPIRE 가 이미 발급한 토큰은 검증 키가 없어져 거부된다)
	rm -f infra/spire/api.env
	-$(DC) --profile spire stop spire-agent spire-server
	$(DC) up -d --wait $(APP_SVC) worker

## --- D1-03 깊은 검사 (Epic 50 · OQ9) — 안전 분류 모델 Qwen3Guard-Gen-0.6B(이미지 빌드 때 고정 판), 응답 뒤 경보만 ---
guard-up:    ## 안전 분류 모델 켜기 [ENV=prod] — guard 기동 → infra/guard/api.env(GUARD_URL, 비커밋) → api·worker 재생성
	$(DC) --profile guard up -d --wait --build --force-recreate guard   # 멈춰 있던 컨테이너가 지워진 옛 네트워크를 가리킬 수 있다
	printf '# make guard-up 이 만든다(비커밋) — 지우면 깊은 검사 끔 (make guard-down)\nGUARD_URL=%s://guard:8080\n' $(if $(filter prod,$(ENV)),https,http) > infra/guard/api.env
	$(DC) up -d --wait $(APP_SVC) worker
injguard-up:  ## 인라인 주입 분류 모델 켜기 [ENV=prod](Epic 64) — injguard 기동 → infra/injguard/api.env(INJGUARD_URL·D1-03 엔진, 비커밋) → api·worker 재생성
	$(DC) --profile injguard up -d --wait --build --force-recreate injguard
	printf '# make injguard-up 이 만든다(비커밋) — 지우면 인라인 모델 끔 (make injguard-down)\nINJGUARD_URL=%s://injguard:8080\nENGINE_OVERRIDES=d1-03=injection_model\n' $(if $(filter prod,$(ENV)),https,http) > infra/injguard/api.env
	$(DC) up -d --wait $(APP_SVC) worker
agw-up:  ## agentgateway MCP 게이트웨이 켜기(Epic 67, local) — 서비스 계정 토큰 → infra/agentgateway/extmcp.env(비커밋) → extmcp·시연 MCP·agentgateway(127.0.0.1:AGW_PORT=3100)
	$(DC_local) exec -T $(APP_SVC) python -m app.agw setup > infra/agentgateway/extmcp.env
	chmod 600 infra/agentgateway/extmcp.env
	$(DC_local) --profile agw up -d --build agentgateway extmcp mcp-demo
agw-down:  ## agentgateway 끄기
	-$(DC_local) --profile agw stop agentgateway extmcp mcp-demo
	rm -f infra/agentgateway/extmcp.env
l2-up:  ## L2 격리 켜기 [ENV=prod](Epic 65) — sandbox-l2(gVisor runsc 고정 판) 기동 → infra/gvisor/api.env(SANDBOX_L2_URL, 비커밋) → api·worker 재생성
	$(DC) exec -T $(APP_SVC) python -c "from app.review import registry_dir; registry_dir().mkdir(parents=True, exist_ok=True)"
	$(DC) --profile l2 up -d --wait --build sandbox-l2
	printf '# make l2-up 이 만든다(비커밋) — 지우면 L2 끔 (make l2-down)\nSANDBOX_L2_URL=%s://sandbox-l2:8080\n' $(if $(filter prod,$(ENV)),https,http) > infra/gvisor/api.env
	$(DC) up -d --wait $(APP_SVC) worker
l2-down:  ## L2 격리 끄기 [ENV=prod] — L2 요구 에이전트는 다시 보류(격리 강등 금지)
	rm -f infra/gvisor/api.env
	-$(DC) --profile l2 stop sandbox-l2
	$(DC) up -d --wait $(APP_SVC) worker
injguard-down:  ## 인라인 주입 분류 모델 끄기 [ENV=prod]
	rm -f infra/injguard/api.env
	-$(DC) --profile injguard stop injguard
	$(DC) up -d --wait $(APP_SVC) worker
guard-down:  ## 안전 분류 모델 끄기 [ENV=prod]
	rm -f infra/guard/api.env
	-$(DC) --profile guard stop guard
	$(DC) up -d --wait $(APP_SVC) worker

## --- 저장 암호화 (NFR-D2, local·prod) — 값마다 DEK, DEK 는 KMS(KMS_BACKEND=builtin|openbao)의 KEK 로 포장 ---
kms-rewrap:  ## 수정 가능한 표(정책·프로파일·발견·승인·표본·OTP 비밀)를 현재 KEK·새 DEK 로 다시 암호화(옛 평문 포함) [ENV=] [ROTATE=1 = builtin KEK 새 버전 먼저] — 원장은 추가 전용이라 제외
	$(if $(ROTATE),$(DC) exec -T $(APP_SVC) python -m app.kms rotate &&) $(DC) exec -T $(APP_SVC) python -m app.kms rewrap
	$(if $(filter prod,$(ENV)),$(DC) kill -s HUP $(APP_SVC),$(DC) restart $(APP_SVC))
	$(DC) restart worker

## --- 내부 상호 TLS (prod 전용, NFR-D3) — 인증서는 tls-init 이 prod-all 마다 확인·갱신(만료 30일 전), 볼륨 tls(비커밋) ---
PG_RELOAD = sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -Atqc "SELECT pg_reload_conf()"' >/dev/null
certs-rotate:  ## [prod] 내부 말단 인증서 즉시 재발급(CA 유지) → PG 재적재 · api SIGHUP(작업 프로세스 하나씩 교체) · web·수집기·worker 는 다음 연결부터 — 재기동 없음
	$(PROD_ONLY)
	$(DC_prod) run --rm --no-deps tls-init rotate
	$(DC_prod) exec -T db $(PG_RELOAD)
	-$(DC_prod) exec -T db-standby $(PG_RELOAD)
	$(DC_prod) kill -s HUP $(APP_SVC)
certs-client:  ## [prod] 외부 도구·ingress 용 클라이언트 인증서 묶음 NAME=<이름> → infra/tls/clients/<이름>/ (비커밋, 90일)
	$(PROD_ONLY)
	@[ -n "$(NAME)" ] || { echo "NAME=<이름> 필요"; exit 1; }
	HOST_UID=$$(id -u) $(DC_prod) run --rm --no-deps tls-init client $(NAME)
