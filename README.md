# AegisMesh

> AI 에이전트 보안 위험 대응 멀티 에이전트 플랫폼 — 도식 「Security Risks in AI Agents」의 위험 항목 하나를 독립 에이전트 하나로 방어하고, 모든 판정을 추가 전용 증적 원장에 남긴다.
> English: [README.en.md](README.en.md) · 정본 요구사항: `.docs/AegisMesh_PRD.pdf`, `.docs/AegisMesh_UI_Design.pdf` · 규제 오버레이: [COMPLIANCE.md](COMPLIANCE.md)

## 현재 구현 범위 (2026-10-08, 로드맵 0~5단계 + P0 플랫폼 + 10차 실행)

| 영역 | 상태 |
|---|---|
| 에이전트 | **80종 — 도식 70 + 보강 10 전부** (커버리지 `전체 80/80 · 엄격 43/43`). 내장 규칙 엔진(L0) + 서드파티 L0·L1 |
| 에이전트 SDK·CLI | `agent.yaml` 규격, Finding/JudgeRequest, core·engine 플러그인, 어댑터 CLI·REST·MCP·**A2A v1.0**(서명 AgentCard·JSON-RPC·호출자 JWT-SVID), 번들 서명, 폐쇄망 번들, **단일 파일 바이너리**(리눅스, 파이썬 불필요) |
| 관문·정책 | 입력·도구·출력·offline 관문 병렬 판정·타임아웃 강등, 선언형 YAML 정책(버전·diff·**단위 시험 통과 시만 배포**·2인 승인 롤백), what-if 시뮬레이터, 사용자 정의 프로파일 |
| 다중 테넌시·인증 | 테넌트별 정책 네임스페이스·**증적 해시 체인**, 교차 접근 403/404, PostgreSQL **RLS**(비특권 역할) 이중, 역할 8종+서비스, 교차 접근 매일 자동 시험 · **조직 SSO**(OIDC 인가 코드+PKCE, MFA acr/amr 필수, IdP 그룹→역할, 미매핑 거부) — 켜면 비밀번호는 비상 관리자만(사유·원장·알림) |
| 로그인 보안 (5차) | **패스키·보안 키(WebAuthn) 2단계**(인증 앱 OTP 대체, 실패 5회 잠금), **DPoP 세션 바인딩**(RFC 9449 — 콘솔이 세션별 키 보관), 새 기기·위치 → 재인증(MSG-030), **탈취 토큰 재사용 → 사용자 세션 전체 폐기·D5-03 사건**, 다른 세션 종료 |
| 로그인·등록 정책 (6차) | **특권 역할(플랫폼·테넌트 관리자·승인자) 2단계 강제** — 수단이 없으면 로그인 직후 등록 화면만, 테넌트가 전원 강제로 상향, 보안 키 **AAGUID 허용목록**(direct attestation) · **IdP back-channel 로그아웃**(세션 전부 폐기)·RP 로그아웃 |
| 워크로드 신원·비밀 | SPIFFE **JWT-SVID** 내장 발급(1시간·50% 자동 회전·JWKS), 서비스 계정 SVID 호출, 동적 시크릿 임대(최소 범위·15분·introspect — **OpenBao 백엔드 선택**(6차): 원문 = OpenBao 토큰, 수명·회수·만료의 원본, 연결 불가 = 거부), 정적 자격증명 점검, 즉시 전체 회전 |
| 샌드박스 | 격리 풀 L0·**L1(별도 프로세스·rlimit·Landlock·seccomp·감사 훅)** 요청 단위 발급·회수, 풀 고갈 시 거부(강등 없음), 탈출 점검 10/10. **L2 = gVisor runsc 브로커**(`make l2-up`, 탈출 점검 23/23, 65th) · L3(microVM) 런타임 없음 → 보류 |
| 관측·성능 | OpenTelemetry(OTLP) 추적·지표·로그 — 판정 traceId = trace id, **수집 단계 마스킹**, SLO · 인라인 증적 **비동기 묶음 적재**(포화 시 표본 강등·원장 기록), 출력 **스트리밍 청크 판정**, 바인딩 캐시 · 실측 2 작업 374 rps / 16 작업 1,776 rps(오류 0) |
| 품질 | 판정 **이의·재판정**(2인 결정·골든셋 편입), 에이전트별 **일 오탐 예산**(80% 경보·임계 제안·초과 경보 전용·7일 복귀), **골든셋 1만 건** 재생(주간), 공개 공격 코퍼스(JailbreakBench·HarmBench·garak 형식) **미탐률** — 페이로드 미보존 |
| 상시 점검 (C3) | `worker` 주기 점검·레드팀·거버넌스·신원 회전·격리 시험, 차단급 발견 → 격리 목록 → 관문 즉시 차단 |
| 등록 심사·장터 | R1~R5(R4 = L1 샌드박스 재생 — L3 노드가 없으면 **L1 대체 + 경보 전용 등록**, 차단 전환 2인 승인(6차)), 장터(신뢰 등급·라이선스) 설치 = 2인 승인 → 심사, 새 버전 무중단 교체 |
| 폐쇄망 | 서명 번들(매니페스트·SHA-256·CycloneDX SBOM) **내부 신뢰 저장소**로 무네트워크 검증·반입, SBOM 취약점 기준, 자체 릴리스 SBOM |
| 증적 원장 | 테넌트별 해시 체인 + 서명 체크포인트 + 한 체인 서명 묶음 오프라인 검증, DB 트리거로 수정·삭제 차단 |
| 사건·승인·거버넌스 | 사건 상관·런북·봉쇄 / 2인 승인(관문·정책 롤백·신뢰 키·장터·레드팀) / 통제 보고서 5종·위험 등록부·자체 점검·상시 레드팀 |
| 도메인 상세·설정 (5차) | D1~D9 상세 27 화면(검사기 = 엔진 신호·진단, 판정 근거), **에이전트 설정 = 정책 agentParams**(보호 대상별 계약 byPrincipal, 정책 값 우선, 변경 시험·영향), 관문 상세·강등·인라인→비동기 재배치(2인), 상시 점검 보드(결정·격리 해제 2인), 삭제 전파·재현 시험, SBOM CLI 게이트 |
| 작업 흐름 (5차) | 즉시 사용 4단계 마법사(보호 대상·비교·부분 차단·해제 = 직전 스냅샷), 승인 결정(지출 상한·보상·2인 진행·신뢰 악용)·트레이·**만료 자동 거절**, 사고 대응 런북 5단계·포렌식 보존(법적 보존)·재현, 업데이트·롤링 교체·**서명 자체 SBOM** |
| 컴플라이언스 (5차, P2) | 공정성 지표(가명 집단 라벨·집단별 차단율·성능 분해·한도 초과 → 위험 등록·영향 평가·공개), **시스템·모델 카드**(ko·en 자동 생성·변경 감지 → 배포 게이트 차단·승인 후 공개·판 이력) |
| 운영 지표·미리보기·보존 (6차) | **성공 지표 12종**(원본 §15.1, 단계 목표 대비·일 스냅샷) · **실제 트래픽 미리보기**(테넌트 옵트인·2인 승인·수집 단계 마스킹·N건·D일) · **증적 보존기한 만료 배치**(2인 승인·서명 체크포인트 경계·법적 보존 앞까지·서명 삭제 증명서·검증 앵커 재시작) · OpenAPI 계약 시험 |
| 접근성·영어 (6차) | **WCAG 2.2 AA 자동 점검 위반 0**(콘솔 전 경로 ko·en, axe-core) · 본문 바로가기·초점 표시·AA 대비 토큰 · **런북 11종·규칙 설명 378개 영어**, en 사건·카탈로그·판정 화면 한글 0 |
| 탐지·측정·운영형 (7차) | **소형 분류기 이중 판정**(D1-01·D1-03, 자체 학습·무결성 고정·규칙이 주 근거, OQ4) · **공개 공격 코퍼스 고정 판 실측**(JailbreakBench·garak·HarmBench·XSTest·GSM8K — 주입·탈옥 미탐 41.1%, 목표 미달 보고) · **재배치(320px)·글자 간격·글자 200%** 전 경로 잘림 0 · en 도메인 상세 화면 한글 0 · **OpenBao 운영형**(raft·감사 장치·봉인 해제, 재기동 뒤 임대 유지) |
| 복구·암호화 (8차) | **백업·복구·동기 복제**(prod: WAL 보관·기본 백업 4시간·동기 대기 서버 — 원장 트랜잭션만 동기 커밋, 복구·장애 조치 훈련 RTO 38~138 s·원장 RPO 0) · **내부 상호 TLS**(web→api·api→db·복제·OTLP, 실행 시 내부 CA·무중단 회전) · **저장 암호화**(값 단위 봉투 암호화, KEK = OpenBao transit 또는 builtin — 원장·정책·발견·승인·표본·OTP 비밀·서명 키 파일, 덤프·WAL·백업 평문 0) · **D1-03 깊은 검사**(검증된 안전 분류 모델 Qwen3Guard-Gen-0.6B, 응답 뒤 경보 — 공개 코퍼스 주입·탈옥 미탐 41.1% → 9.7%) |
| 운영 마감 (9차) | **깊은 검사 실효화**(의심 우선 선별 대기열 — 부하 210 rps 에서 주입 경보 75%, 경보 → 주체·세션 격리로 다음 요청 인라인 차단, 해제 2인·기한) · **백업 외부 복사**(SeaweedFS S3·상호 TLS, 파일마다 KMS 봉투 암호화 — 객체 저장만으로 복구 RTO 93 s, 평문 0) · **SPIRE**(Workload API·ES256 JWT-SVID, `IDENTITY_BACKEND` 전환) · **보안 키 증명 체인**(FIDO MDS3 이미지 고정 판 — GlobalSign R3 지문·서명자·CRL 검증, packed 체인·AAGUID 확장·MDS 상태, 자기 신고 AAGUID 불신) · **지오 IP·불가능한 이동**(DB-IP Lite 고정 판, 대도시권 망 전환 통과·불가능한 속도 → 재인증·D5-03 경보) · **OpenBao 3노드 raft**(transit 자동 봉인 해제·TLS 1.3 상호 인증·리더 장애 중 임대 실패 0) · **CLI 한/영**(`--lang`·`AEGIS_LANG`) |
| 운영 마감 (10차) | **원장 평문 제거**(2인 승인 창 안에서만 트리거가 '평문 → 암호문' 허용 — 134만 건 → 0, 해시 체인 그대로) · **고정 판 갱신**(`make pins-refresh`) · **garak 레드팀**(공격 성공률 45.3% → 24.7%) · **발견 버스**(NATS JetStream, 누락·중복 0) · **폐쇄망 미러**(레지스트리 미러만으로 k3s 설치) · **TPM·android-key 증명** · **보조기술 점검**(접근성 트리 4종) · **인라인 주입 모델**(직접 주입 미탐 41.1% → 22.5%) · **L2 격리 gVisor**(runsc 브로커, 탈출 23/23 막힘) · **agentgateway**(MCP tools/call → 도구·출력 관문) · **HSM 봉인 해제**(SoftHSM2 PKCS#11, 무인 ~1 s) · 노드당 처리량 = 공유 VM 최고 1,797 rps 를 리허설 값으로 수용(2,000 확인은 전용 노드) |
| 설치·첫 실행 | 헬름 차트(k3d 실제 설치 리허설) · compose · CLI, 사전 점검, **첫 실행 마법사 5단계**(관리자·SSO → 신원·비밀 → 증적·관측 → 대상·첫 판정 → 설치 검증, 30분 목표 경과) |
| 콘솔 | Next.js 74 경로 틀 — 로그인(SSO)·첫 실행·⌘K 팔레트·알림·위험 지도·카탈로그·장터·관문·정책·시뮬레이터·미리보기·토폴로지·판정(이의)·사건·승인·원장·보고서·관측·SLO·품질·레드팀·X 페이지·테넌트·사용자·SSO·신원·샌드박스·폐쇄망·데이터 보호·설치 · **본문·보고서 한국어·영어** · **5차 추가**: 도메인 상세(`/domains/[d]/[view]`·검사·도구 호출·근거·계보)·관문 상세·강등·즉시 사용 마법사 4단계·승인 결정·트레이·대응 런북·업데이트·공정성·카드·2단계 인증·재인증 · **6차 추가**: 성공 지표·증적 보존·2단계 등록·로그인 정책·표본 미리보기 |

후속(미구현): **첫 요청 인라인 차단 기준 미탐은 41.1% 그대로**(깊은 검사는 응답 뒤 경보 → 격리로 같은 주체의 *다음* 요청부터 차단, 운영 트래픽 전수 검사는 GPU·증설 필요), 암호화 전 원장 기록(보존기한까지 평문), 외부 복사의 다른 사이트·외부 S3 실배치(리허설은 같은 호스트), 봉인 해제기의 클라우드 KMS·HSM(리허설은 같은 호스트 Shamir), MDS3·DB-IP 월간 판 자동 갱신(판 교체 = 재빌드), TPM·android-key 증명 형식(packed 만), 화면 낭독기 등 보조기술 실사용 점검, L2·L3 microVM, agentgateway·NATS·ClickHouse, 외부 탐지 엔진(garak) 어댑터, 전용 노드 NFR-P1 2,000 rps 확인, 이미지·차트 레지스트리 미러.

## 구성

```
agents/<id>-<slug>/        에이전트 1종 = agent.yaml + core.py(순수 함수) + engines/ + tests/{golden,attacks,baseline.json}
aegis/                     에이전트 SDK — schemas · manifest · agent 로더 · decide · engine · patterns · harness · coverage · ledger_verify · airgap · goldenset · adapters/{rest,mcp,a2a} · cli
app/                       제어 API (FastAPI) — registry · orchestrator · gating · policy · profiles · findings · approvals · ledger · scanner · worker
                           · auth · sso · tenancy · identity · secrets_broker · sandbox(+sandbox_child) · telemetry · airgap · market · console · admin
                           · evidence_writer(비동기 증적) · hotcache · quality
                           · review(+review_runner) · incidents · reports · governance · redteam · api/
apps/web/                  콘솔 (Next.js App Router · React 19 · Tailwind 4) — 서버 컴포넌트 + 서버 액션, 세션은 httpOnly 쿠키
                           lib/i18n.ts L()·lib/en.ts 영어 카탈로그(한국어 원문 = 메시지 ID) · scripts/i18n-codemod*.mjs
policies/ · profiles/      기본 정책 · 즉시 사용 프로파일 5종
controls/*.yaml            통제 카탈로그 (OWASP 2종은 매니페스트 standards 에서 자동 매핑)
runbooks/*.md              도메인별 사고 대응 런북 (D1~D10·X)
observability/masking.yaml 수집 단계 마스킹 규칙 (단일 원천) → infra/otel/collector.yaml (생성물)
airgap/vulndb.json         내부 취약점 DB 기본값 (폐쇄망 번들로 갱신)
diagram_items.json         도식 70 항목 + 보강 10 (누락 검증의 기준)
scripts/                   fetch_mds.py(FIDO MDS3 빌드 때 받기, 표준 라이브러리) · verify_coverage.py (CI 게이트) · new_agent.py · gen_otel_config.py · build_cli.py · k8s_rehearsal.sh · loadtest.py · idp_realm.py · train_classifier.py(OQ4 소형 분류기 — 재현 가능한 학습, 출력 sha256 을 D1-01·D1-03 분류기 엔진 `MODEL_SHA256` 에 고정) · bao_setup.py(OpenBao dev·운영형 구성)
deploy/helm/aegismesh/     헬름 차트 (post-install 마이그레이션 Job·existingSecret·PVC)
infra/keycloak/            시험 IdP 렐름 템플릿 (생성물 import/ 는 비커밋)
migrations/                Alembic 0001~0005 + 0006 테넌시·인증·RLS · 0007 정책 운영·사용자 정의 프로파일 · 0008 신원·임대 · 0009 신뢰 저장소·반입·장터
                           · 0010 조직 SSO · 0011 사건 총계 · 0012 판정 라벨·골든 표본(RLS) · 0013 보호 대상 · 0014 로그인 보안 · 0015 트래픽 표본
                           · 0016 원장 보존 삭제 · 0017 로그인 정책 · 0018 임대 백엔드 · 0019 DR 상태 · 0020 격리 기한 · 0021 세션 지오
app/ (9차)                 fido(MDS3·증명 체인) · geo(지오 IP·불가능한 이동) · spire · offsite · openbao(다중 노드·상호 TLS) · aegis/i18n(CLI 한/영)
app/ (10차)                ledger_rewrap(원장 재암호화) · pins · garak · bus(NATS) · agw(agentgateway 준비) · sandbox L2(gVisor 브로커 연결) · registry ENGINE_OVERRIDES
infra/ (10차)              injguard(주입 모델) · gvisor/broker.py · extmcp(ExtMCP gRPC) · agentgateway · openbao/hsm(SoftHSM2) · garak · nats · mirror
```

## 실행 모델

실행은 **docker compose 전용**, 모드는 **local / prod**.

| 모드 | compose 파일 | env 파일 | DB | 서비스 |
|------|--------------|----------|----|--------|
| local | `docker-compose.yml` + `docker-compose.local.yml` | `.env.local` (커밋) | SQLite `/app/data/app.db` | api(dev, 소스만 핫리로드·자동 마이그레이션·시드) · worker · web(next dev) · otel-collector |
| prod | `docker-compose.yml` + `docker-compose.prod.yml` | `.env.prod` (비커밋) | PostgreSQL 17 (max_connections 300, WAL 보관·원장 동기 복제) | api(runtime, `WEB_CONCURRENCY` 작업 수 기본 2, 비루트) · worker · web(standalone) · db · db-standby · db-backup · otel-collector |

| 서비스 | 포트 | 비고 |
|---|---|---|
| api | `127.0.0.1:8000` | `/health` 는 실제 `SELECT 1`, `/docs` OpenAPI. 모든 `/v1` 은 인증 필요. **prod 는 https + 클라이언트 인증서 필수**(`make certs-client`) |
| web | `127.0.0.1:3000` | 콘솔. 서버 측에서 `API_URL=http://api:8000` 로 호출 (브라우저 → API 직접 호출 없음) |
| worker | — | 상시 점검·레드팀·거버넌스·신원 회전·테넌트 격리 시험 `python -m app.worker` |
| otel-collector | 내부 4317/4318 | `otel/opentelemetry-collector-contrib:0.162.0`, 마스킹 후 debug 내보내기 |
| db (prod) | 내부 5432 | 헬스체크 `pg_isready`, 앱은 `aegis_app` 역할로 RLS 적용 |
| e2e (local `e2e` 프로파일) | — (콘솔 네트워크 공유) | `infra/e2e` = Playwright 1.55 + Python + axe-core 4.10 — `make e2e-passkey`·`make e2e-a11y` 1회 실행 |
| keycloak (local `idp` 프로파일) | `127.0.0.1:8080` | 조직 SSO 시험 IdP — `make idp-up` (렐름 aegis, 클라이언트 aegismesh-console, LoA pwd/mfa) |
| bao (local `bao` 프로파일) | `127.0.0.1:8210` (`BAO_PORT`) | OpenBao 2.4.1 dev 서버 — `make bao-up` 이 정책·토큰 역할·브로커 토큰을 만들고 api·worker 를 OpenBao 임대로 재기동 (8200 은 다른 프로세스가 쓸 수 있어 8210) |
| bao-server (local `bao-server` 프로파일) | `127.0.0.1:8210` (`BAO_PORT`, bao 와 둘 중 하나) | OpenBao 2.4.1 운영형 리허설 — raft 저장(`baodata`)·설정 선언 감사 장치(`baoaudit`)·수동 봉인 해제 · `make bao-up MODE=server` · `make bao-unseal` |
| corpus (local `corpus` 프로파일) | — (1회 실행) | 공개 공격 코퍼스 고정 판 이미지(`infra/corpus` — GitHub 고정 커밋 데이터 파일·SHA256SUMS·PROVENANCE) → `corpora` 볼륨, api·worker 가 `/corpora` 읽기 전용 · `make corpus-eval` |
| db-standby · db-backup (prod) | — | 재해 복구(NFR-A5) — 동기 대기 서버(첫 기동 때 주 서버 복제, 스트리밍이 붙으면 `synchronous_standby_names` 등록) · 주기 기본 백업(`DB_BACKUP_INTERVAL_SEC`, 볼륨 `dbbackup` = 기본 백업 + 주 서버 WAL 보관) |
| db-drill (prod `drill` 프로파일) | — | 복구 훈련 전용 — 전용 볼륨 `dbdrill` 에 기본 백업 + 보관 WAL 재생·승격, 끝나면 삭제(운영 볼륨 무변경) · `make db-restore-drill ENV=prod` |
| objstore · backup-ship (prod) | — (S3 8333, 상호 TLS) | 백업 외부 복사(NFR-A5) — SeaweedFS 4.48 S3(클라이언트 인증서 필수, gRPC 도 상호 TLS, 나머지 포트는 컨테이너 안) · backup-ship 이 기본 백업·보관 WAL 을 파일마다 KMS 봉투 암호화(AES-256-GCM 4 MB 조각)해 `OFFSITE_INTERVAL_SEC` 마다 복사, 원격도 `DB_BACKUP_KEEP` 으로 정리 |
| spire-server · spire-agent (`spire` 프로파일) | — (내부 8081) | 워크로드 신원 SPIRE 1.15.3(Epic 53) — join token 노드 별칭 `node/api`, agent 는 api 와 PID 네임스페이스를 함께 써서 uid 로 증명, Workload API 로 JWT-SVID(ES256). `make spire-up|spire-down [ENV=prod]` |
| tls-init (prod) | — (1회 실행) | 내부 상호 TLS(NFR-D3) — 실행 시 만든 내부 CA·말단 인증서(db·replicator·api·web·otel, 90일)를 볼륨 `tls`(비커밋)에 두고 만료 30일 전 재발급. 서비스는 자기 하위 경로만 `/tls` 에 읽기 전용. prod 의 api 는 `https` + 클라이언트 인증서 필수 |
| guard (`guard` 프로파일, local·prod) | — (내부 8080) | 안전 분류 모델 Qwen3Guard-Gen-0.6B(Apache-2.0, 고정 커밋·가중치 해시를 이미지 빌드에서 검증, 실행 중 네트워크 없음) — D1-03 **응답 뒤 깊은 검사**(경보만, 차단 불가). prod 는 클라이언트 인증서 필수 · `make guard-up [ENV=prod]` |
| agentgateway · extmcp · mcp-demo (local `agw` 프로파일) | 127.0.0.1:3100(`AGW_PORT`) | MCP 게이트웨이(Epic 67) — agentgateway v1.6.0(digest 고정)의 MCP 가드레일이 모든 `tools/call` 을 ExtMCP 정책 서버(gRPC, 고정 proto)로 → AegisMesh 도구 관문(요청)·출력 관문(결과). 차단·승인 필요는 도구 오류 결과, 결과 속 비밀은 무해화, 정책 서버 장애 = 거부(failClosed). 시연 MCP 서버는 도구를 흉내만 · `make agw-up` |
| sandbox-l2 (`l2` 프로파일, local·prod) | — (내부 8080) | L2 격리 브로커(Epic 65) — gVisor runsc 고정 판(아키텍처별 sha256)으로 L2 요구 서드파티 에이전트의 판정·심사 재생을 샌드박스(네트워크 없음·읽기 전용 루트 FS + 1회용 덧씌움)에서. 비루트·능력 없음·읽기 전용 컨테이너(사용자 이름공간 때문에 seccomp·AppArmor 만 unconfined), 번들은 appdata/registry 읽기 전용. prod 는 클라이언트 인증서 필수 · `make l2-up [ENV=prod]` |
| injguard (`injguard` 프로파일, local·prod) | — (내부 8080) | 인라인 주입 분류 모델(Epic 64) — protectai/deberta-v3-base-prompt-injection-v2(Apache-2.0) 고정 커밋 ONNX(sha256 검증)·ONNX Runtime CPU, 입력 앞·뒤 96 토큰 창. D1-03 엔진 `injection_model` 이 예산 안(60 ms)에서 묻고 넘으면 이중 판정. 영어 모델이라 라틴 문자 입력만. prod 는 클라이언트 인증서 필수 · `make injguard-up [ENV=prod]` |

local 과 prod 는 같은 호스트 포트를 쓴다 — 동시에 띄우지 말고 `make local-stop` 후 prod 리허설.

## 빠른 시작

```bash
make preflight
make local-all                                   # api + web (첫 기동 시 마이그레이션·시드 자동)
curl http://127.0.0.1:8000/health
make local-logs | grep 부트스트랩                  # 첫 실행 1회용 토큰(24h) — 분실 시 make admin-token
open http://127.0.0.1:3000/setup                 # 콘솔 첫 실행: 비상 관리자 + 첫 테넌트 → 로그인
TOKEN=$(curl -s http://127.0.0.1:8000/v1/auth/login -H 'content-type: application/json' \
        -d '{"username":"<id>","password":"<pw>"}' | jq -r .token)
curl -X POST http://127.0.0.1:8000/v1/profiles/tool-agent:apply -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' -d '{"target":"agent.example"}'
make test && make test-web && make coverage
make local-stop
```

prod 리허설:

```bash
cp .env.example .env.prod      # 없을 때만 — CHANGE_ME 를 Secret Manager 값으로 교체
make local-stop
make prod-build
make db-migrate ENV=prod && make db-seed ENV=prod && make db-ping ENV=prod
make admin-token ENV=prod      # 부트스트랩 토큰 → 콘솔 /setup
make prod-stop
```

## 운용 3모드

| 모드 | 사용 |
|---|---|
| M1 독립 | `python -m aegis run d1-05 --input req.json` · `python -m aegis serve d2-03 --protocol rest --port 8080` · `python -m aegis serve d1-07 --protocol mcp --stdio` · `python -m aegis serve d1-03 --protocol a2a --port 9090 --key card.key [--trust-jwks <플랫폼>/v1/identity/jwks]` (A2A v1.0 서명 AgentCard `/.well-known/agent-card.json` + JSON-RPC `SendMessage`) · `python -m aegis a2a card|send <url> --trust jwks.json` (카드 서명 검증 후 호출, 신뢰 고정 없으면 거부) |
| M2 연계 | `POST /v1/judge:batch` — 관문에 바인딩된 에이전트를 병렬 호출하고 정책으로 합성 |
| M3 즉시 사용 | 콘솔 `/instant` 또는 `POST /v1/profiles/{id}:apply` — 관측만(observe)·부분 차단(partial)·전체 차단(enforce) |

`aegis` CLI = `python -m aegis` (`list` · `eval <id>|--all [--update-baseline]` · `coverage` · `verify-bundle <file>` · `keygen --out` · `bundle <dir> --key --key-id` · `airgap build|verify` 포함 — 폐쇄망 번들은 네트워크 없이 검증).

## API

모든 `/v1` 호출은 `Authorization: Bearer am1.…`(로그인 세션 또는 서비스 계정 API 토큰)이 필요하다. 플랫폼 사용자는 `X-Aegis-Tenant: <id>` 로 테넌트 범위를 고른다.

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET·POST | `/v1/auth/config`, `/v1/auth/bootstrap`, `/v1/auth/login` | (공개) 로그인 구성·첫 실행 부트스트랩(1회용 토큰)·로그인 — 5회 실패 시 15분 잠금. 조직 SSO 사용 중에는 비상 관리자만(`reason` 필수, 원장·알림) |
| GET·POST | `/v1/auth/oidc/start?redirect=&next=`, `/v1/auth/oidc/callback` | (공개) 조직 SSO — 인가 코드 + PKCE(S256), state·nonce·verifier 는 서버 보관(10분·1회용), RS256 ID 토큰·MFA(acr/amr)·그룹→역할 |
| GET·PUT·POST | `/v1/auth/sso`, `/v1/auth/sso/mappings`, `/v1/auth/sso:test` | 조직 SSO 설정·IdP 그룹→역할 매핑·연결 시험(플랫폼 관리자) — 미매핑 사용자 거부 |
| GET·POST | `/v1/auth/me`, `/v1/auth/logout`, `/v1/auth/sessions`, `/v1/auth/sessions/{id}:revoke` | 현재 주체·권한·범위 · 로그아웃 · 내 세션(기기·위치 = IP 대역 + 지오 `geo` "KR · Seoul"/private/unknown) · 세션/토큰 회수 |
| GET·POST | `/v1/evidence/rewrap`, `/v1/evidence/rewrap:request` | 원장 저장 재암호화(Epic 57) — 평문 기록 수·구간·창(서명 증명서)·현재 KEK / 2인 승인 요청(privacy·플랫폼). 승인되면 창(`LEDGER_REWRAP_WINDOW_SEC`)이 열리고 worker·`make ledger-rewrap` 이 묶음 실행 — 트리거는 창 안 '평문 → 암호문, 다른 열 불변' 만 허용 |
| GET | `/v1/evidence/bus` | 발견 버스 상태(Epic 60) — NATS 스트림 메시지 수·중계 커서·지연(원장 seq 차이). 플랫폼 범위 |
| GET | `/v1/quality/garak` | garak 최근 결과(Epic 59) — garak 판·보호 대상·무방비/관문 공격 성공률(전체·탐침별). 페이로드 원문 없음 |
| GET | `/v1/auth/mds` | FIDO MDS3 스냅숏 상태(Epic 54) — 번호·다음 갱신·낡음·기종 수·유출/우회 보고 기종 수·서명자·고정 루트(GlobalSign R3 sha256). 스냅숏이 없으면 `loaded: false` + 사유 |
| GET | `/v1/auth/geoip[?ip=]` | 지오 IP DB 상태(Epic 55) — DB-IP Lite 월·빌드 날짜·sha256·같은 위치 거리·불가능한 이동 임계. `ip` 를 주면 분류(public·private·unknown)·나라·시도·대역 |
| GET·POST·PATCH | `/v1/users`, `/v1/users/{id}`, `/v1/users/{id}/tokens`, `/v1/roles`, `/v1/authz:check` | 사용자·역할(자기 역할 변경 불가) · 서비스 계정 API 토큰(원문 1회) · 권한 확인 |
| GET·POST·PATCH | `/v1/tenants`, `/v1/tenants/{id}`, `/v1/tenants:isolation-test`, `/v1/tenants/isolation-test` | 테넌트(정책 NS·원장 체인) · 교차 접근 차단 시험 7항목 |
| POST | `/v1/judge?agent=<id>` | 단일 판정 — 본문은 M1 과 같은 JudgeRequest |
| POST | `/v1/judge:batch` | 관문 판정 `{gate, request, target?, agents?, stage?, policy?}` — 증적은 비동기 묶음 적재(응답 `evidence`: queued·sampled_out·dropped) |
| POST | `/v1/judge:stream` | 스트리밍 출력 청크 판정(NFR-L3) `{chunk, held, seq, streamId?, final?, target?/agents?}` → `{verdict, emit, held, stop}` — 끝 128자 보류로 청크 경계 비밀 탐지, 서버 무상태 |
| POST·GET | `/v1/findings/{id}:appeal`, `/v1/findings/{id}/appeals`, `/v1/appeals`, `/v1/appeals/{id}:decide` | 판정 이의·재판정(SCR-O02) — 마스킹 재현 표본 교차 재판정, 신청자 아닌 사람이 fp·tp 결정, 오탐이면 골든셋 편입 |
| GET·POST | `/v1/quality`, `/v1/quality/fp-budget`, `/v1/quality/fp-budget:enforce`, `/v1/quality/golden:replay`, `/v1/quality/corpora` | 품질(SCR-Q04) — 일 오탐 예산(80% 경보·임계 제안·초과 경보 전용·7일 복귀), 골든셋 1만 건 재생, 공개 공격 코퍼스 미탐률(페이로드 미보존) · 코퍼스 `kind`(attack 미탐률·benign 오탐률)·`variant`(dual·rules-only — 분류기 끔 비교)·`scope`(injection·harmful-request) · 요약 `corpusHeadline` |
| GET·POST | `/v1/agents`, `/v1/agents/{id}` | 카탈로그·상세(실측 품질·규칙 설명 — `rules` 한국어 원문 + `rulesEn` 영어, 번들의 `rules.en.yaml`)·등록 — 매니페스트(R1만) 또는 서명 번들 `AgentBundle/v1`(R1~R5 심사) |
| GET | `/v1/agents/{id}/reviews` | 등록 심사 기록(단계별 결과) |
| GET·POST | `/v1/publishers` | 신뢰 게시자 Ed25519 공개키 (R2) |
| GET | `/v1/risk-items`, `/v1/coverage` | 도식 80 항목 적용 현황 · 누락 검증 |
| GET·POST | `/v1/profiles`, `/v1/profiles/{id}`, `/v1/profiles/{id}:apply` | 프로파일 · 적용 |
| GET·POST | `/v1/applications`, `/v1/applications/{id}:release` | 활성 적용 · 해제 |
| GET·POST | `/v1/policies/{id}`, `/v1/policies` | 정책 조회 · 새 버전(YAML) |
| GET·POST | `/v1/policies`, `/v1/policies/{id}/versions`, `/v1/policies/{id}/diff?from&to`, `/v1/policies:test`, `/v1/policies/{id}:rollback` | 정책 목록·버전·diff · 초안 단위 시험(저장 없음) · 롤백 요청(2인 승인 후 적용). 배포 `POST /v1/policies` 는 `tests` 실패 시 422 |
| POST | `/v1/policies:simulate` | 판정 시뮬레이터 — 배포 vs 초안 정책, 차단·기록 없음 |
| GET | `/v1/gates?tenant&hours` | 관문 구성·예산·하드 타임아웃·바인딩·failMode·p95·강등 기록 |
| GET | `/v1/gates/{gate}?hours` | 관문 상세(SCR-D02) — 에이전트 p50/p95/p99·예산 몫·지연 분포·재배치 제안·비용·SLO 경보 |
| GET | `/v1/gates/degradation?days` | 강등 현황(SCR-D06) — 현재 강등·경보 전용·실패 모드별 동작·failMode·강등 이력 |
| GET | `/v1/gates:status` | 상단 바 관문 칩 — 최근 15분 p95·강등(closed/open) |
| POST | `/v1/gates/{gate}/relocations{,:ignore}` | 재배치 적용·복귀 요청(2인 승인 → 정책 relocated) / 무시(사유 원장) |
| GET·POST·PUT | `/v1/agents/{id}/config{,:test}` | 에이전트 설정(정책 agentParams) 조회·변경 시험(저장 없음)·배포(사유 필수) |
| POST | `/v1/agents/{id}:inspect` | 도메인 상세 검사기 — 붙여 넣은 요청 판정·엔진 신호·진단(explain), 저장 없음 |
| GET | `/v1/findings/{id}/inspect` | 입력 검사 뷰어(SCR-E02) — 근거 + 판정 기록의 요청 모양(원문 없음) |
| GET | `/v1/domains/d1/exfil` · `/v1/domains/d2/isolation` | 유출 차단 현황(허용목록 이력·카나리·설계 원칙) · 격리·자격증명·접근 결정 |
| POST | `/v1/domains/d2/isolation:regress?n` | 교차 조회 회귀 시험(테넌트·주체·세션 경계 합성 요청 → D2-02, 누출 수) |
| GET·POST | `/v1/erasure{,/{id}/stores,/{id}:verify,/{id}:certify}` | 삭제 전파(해시 식별자·저장소 보고·D2-07 재검사·증적 발행, privacy 권한) |
| GET·POST | `/v1/recall-tests` | 학습 데이터 재현 시험·배포 게이트(D2-05, 출력 표본 미저장) |
| GET | `/v1/domains/d3/calls{,/{trace}}` · `/v1/domains/d3/{sandbox,registry}` | 도구 호출 판정 상세·샌드박스 풀·쿼터·상승 경로·도구 레지스트리 (SCR-G02~G04) |
| GET | `/v1/domains/d4/grounding/{finding}` · `/v1/domains/d4/{decisions,propagation}` | 근거성·인용 · 결정 신뢰도·논리·규정 · 오정보 전파·신뢰 지표 (SCR-H02~H04) |
| POST | `/v1/domains/d4/corrections` | 전파 지점 정정 상태·소급 정정 (원장 correction) |
| GET | `/v1/domains/d5/{identity,tokens,authz}` · `POST /v1/domains/d5/authz:drift-scan` | 워크로드 신원·카드·바인딩 · 토큰 감시(재사용·수신자) · 인가·위임·권한 드리프트(D5-07) (SCR-I02~I04) |
| GET | `/v1/domains/d6/{autonomy,runs,runs/{trace},budgets}` | 자율 레벨·과업 계약(보호 대상별) · 실행 계보·루프 · 자원 쿼터·지출·금전 승인 (SCR-J02~J04) |
| GET·PUT | `/v1/agents/{id}/config?principal=` | 보호 대상별 계약(byPrincipal) — 그 주체의 요청에서 공통 값보다 우선 |
| GET | `/v1/domains/artifacts/{group}` | 상시 점검 대상·최근 점검 근거·격리·결정 (review·sbom·integrity·index·posture·runtime·network) |
| POST | `/v1/domains/decisions` | 공급망·격리 결정 — 2인(허용 예외·핀 갱신·격리 해제·쓰기/네트워크 도구 승인)은 승인함 |
| GET | `/v1/domains/d8/{memory,context,bias}` | 메모리 탐색·쓰기 승인 · 컨텍스트 구획(T0~T3) · 검색 출처 편향 (SCR-L02~L04) |
| GET·POST | `/v1/observability`, `/v1/observability:mask-test`, `/v1/observability:test-log` | 관측 파이프라인·전송 통계·마스킹 규칙·SLO·오탐 예산 · 규칙 미리보기 · 시험 로그 전송(수집 단계 치환 확인) |
| GET | `/v1/observability/dr` | 재해 복구 상태(NFR-A5) — 역할·대기 서버(streaming·sync·지연)·원장 동기 여부(`ledgerRpo0`)·WAL 보관(건수·실패·최근 경과)·목표·최근 훈련. local(SQLite)은 `applicable: false` |
| GET | `/v1/observability/tls` | 내부 상호 TLS 상태(NFR-D3) — 구간·인증 방식·CA/말단 인증서 만료·일련번호·이 api 의 DB 연결(TLS·sslmode)·OTLP 클라이언트 인증서. local 은 `enabled: false` |
| GET | `/v1/observability/kms` | 저장 암호화 상태(NFR-D2) — KMS·KEK 버전·표별 암호화 비율(표본 1000행 + 전체 건수)·최근 증적 1000건·서명 키 파일 포장 여부. 값은 내보내지 않는다 |
| GET·POST | `/v1/identity/jwks`(공개), `/v1/identity`, `/v1/identity:rotate`, `/v1/identity/svid`, `/v1/identity:verify`, `/v1/identity/static-credentials` | 워크로드 신원(SPIFFE JWT-SVID, 1시간·50% 자동 회전) · 즉시 전체 회전 · 서비스 계정 SVID 교환(API 주체로 사용) · 검증 · 정적 자격증명 점검 |
| GET·POST | `/v1/secrets/leases`, `/v1/secrets/leases/{id}:renew`, `:revoke`, `/v1/secrets:introspect` | 동적 시크릿 임대(최소 범위·최대 15분·원문 1회) · 갱신·회수 · 하위 도구 확인 |
| GET | `/v1/secrets/backend` | 임대 엔진 상태 — `builtin` 또는 OpenBao(주소·봉인·판·ok·응답 노드 `node`·`standby`·`tls`). OpenBao 면 임대 원문 = OpenBao 토큰(역할 `aegis-lease`, 생성 기준 15분 상한), 확인은 OpenBao 에 묻고 연결 불가면 거부(fail-closed), OpenBao 에서 회수·만료되면 목록도 맞춘다 |
| GET·POST | `/v1/sandbox`, `/v1/sandbox:probe?level=L1\|L2` | 격리 풀(L0~L3) 용량·사용·대기·거부·회수와 커널 잠금 수단(Landlock·seccomp), L2 는 runsc 판·커널·기동 시간·브로커 통계 · 탈출 점검(L2 = gVisor 경계 + 안쪽 잠금 층, 원장 기록) |
| GET·POST | `/v1/trust-keys`, `/v1/trust-keys:export`, `/v1/trust-keys/{id}:revoke` | 내부 신뢰 저장소(추가·폐기 2인 승인) · 오프라인 검증용 신뢰 번들 |
| GET·POST | `/v1/airgap/imports`, `/v1/sbom` | 폐쇄망 번들 반입(서명→해시→SBOM 취약점→적용, 실패 시 422 + 기록) · 자체 릴리스 SBOM(CycloneDX) |
| GET·POST·DELETE | `/v1/targets`, `/v1/targets/{id}` | 보호 대상(엔드포인트·관문 삽입·모델 공급자·MCP 서버·이그레스 허용목록·SPKI 핀) — 외부 모델 금지 프로파일의 외부 호출은 승인 후, 적용 중 삭제 409 (SCR-C05) |
| GET | `/v1/profiles/{id}/compare?target=` | 프로파일 변경 비교 — 추가·제외 에이전트, 관문 지연, 증적 보존, 외부 모델, 격리 요구 (SCR-C04) |
| POST | `/v1/instant:apply`, `/v1/instant:rollback` | 단계 적용(관측·부분 = 선택 도메인만 차단·전체 = 승인, 강등 확인 필수) · 해제 = 직전 스냅샷 복귀 (SCR-C07) |
| GET | `/v1/approvals:tray`, `/v1/approvals/{id}/context` | 승인·작업 트레이(만료 임박 순·반복 요청) · 결정 문맥(행동·지출 상한·보상·자율 등급·신뢰 악용) — 만료 승인 결정은 409 + 자동 거절 (SCR-B07·O06) |
| GET·POST | `/v1/incidents/{id}/response`, `/v1/incidents/{id}/steps`, `:preserve`, `:replay` | 사고 대응 런북 5단계(실행·승인·결과 원장) · 포렌식 보존(법적 보존·원문 미보존) · 재현(판정 일치) (SCR-O07) |
| GET·POST | `/v1/updates`, `/v1/updates/agents/{id}:reload`, `/v1/updates/sbom` | 버전·교체 이력 · 에이전트 롤링 교체(품질 게이트 실패 = 기존 유지) · 자체 SBOM + Ed25519 분리 서명(JWKS 검증) (SCR-R05) |
| GET·POST·PUT | `/v1/compliance/fairness`, `:measure`, `/fairness/assessments`, `/fairness/disclosure` | 공정성·윤리 지표 — 집단별 차단율(요청 `subject.groups` 가명 범주 + 문자 체계)·레드팀 코퍼스 성능 분해·추세, 지금 측정(d10-05 → 한도 초과 = 위험 등록), 영향 평가 문서, 격차 공개 설정 (SCR-N06) |
| GET·POST | `/v1/compliance/cards`, `:generate`, `/cards/{subject}/doc?lang=`, `/cards/{subject}:publish`, `/v1/compliance/deploy-gate` | 시스템·모델 카드 — 메타데이터에서 ko·en 자동 생성, 입력 지문 변경 = 갱신 필요(배포 게이트 차단·D10-06), 검토 → 승인 후 공개(판 이력 원장) (SCR-N07) |
| POST | `/v1/auth/login` (+ `DPoP` 헤더) → `{token}` 또는 `{mfa}`, `/v1/auth/mfa:verify` | 2단계 인증 — 패스키·보안 키(WebAuthn) 우선·인증 앱 OTP 대체, 실패 5회 15분 잠금. 로그인 요청의 DPoP 증명 키에 세션을 묶는다(RFC 9449) (SCR-B02) |
| GET·POST·DELETE | `/v1/auth/mfa`, `/v1/auth/webauthn/register:options`, `/v1/auth/webauthn/register`, `/v1/auth/webauthn/{id}`, `/v1/auth/totp:setup`, `:confirm`, `/v1/auth/totp` | 내 2단계 수단 — 패스키 등록(challenge 1회·origin·rpId·UV 검사)·삭제, OTP 등록(봉인 저장)·해제 |
| POST | `/v1/auth/reauth:options`, `/v1/auth/reauth`, `/v1/auth/sessions:revoke-others` | 새 위치·기기 감지 세션 재인증(MSG-030) · 다른 세션 모두 종료. 바인딩 토큰을 증명 없이·다른 키로·증명 재사용 → 사용자 세션 전체 폐기 + D5-03 사건(FR-D5-03) |
| GET·POST | `/v1/metrics/success`, `/v1/metrics/success:snapshot` | 성공 지표 12종(원본 PRD §15.1) 실측·1단계/정상 운영 목표 비교·추세 · 일 1회 스냅샷(원장 전체 검증, 원장 `kpi`) |
| GET·PUT·DELETE | `/v1/traffic-samples`, `/v1/traffic-samples/settings`, `/v1/traffic-samples/{id}/label` | 미리보기용 실제 트래픽 표본(OQ1) — 기본 미보존, 켜기·확대 2인 승인, 수집 단계 마스킹·N건·기한, 라벨 · 미리보기 `source=traffic` |
| GET·POST | `/v1/evidence/retention`, `/v1/evidence/retention:request`, `/v1/evidence/purges/{id}` | 증적 보존기한 만료 — 삭제 API 아님: 서명 체크포인트까지·법적 보존 앞까지 2인 승인 배치, 서명 삭제 증명서, 검증은 앵커에서 재시작 (worker 일 1회 요청) |
| GET·PUT | `/v1/tenants/{id}/auth-policy` | 로그인 정책(OQ3) — 2단계 강제 범위 `privileged`(기본: 플랫폼·테넌트 관리자·승인자) 또는 `all`, 보안 키 AAGUID 허용 목록(direct attestation). 수단 없는 강제 대상은 로그인 뒤 등록 경로만(`enrollRequired`, 그 밖은 401 `mfa_enrollment_required`) · 변경 user.admin |
| POST | `/v1/auth/oidc/backchannel-logout`, `/v1/auth/logout` `{postLogoutRedirect}` | (공개) IdP back-channel 로그아웃(`logout_token` RS256·jti 1회) → 그 사용자 세션 전부 폐기 · SSO 세션 로그아웃은 `idpLogout`(end_session_endpoint) 반환 |
| POST | `/v1/agents/{id}:promote` | L3 노드 없이 L1 대체 심사된 경보 전용 에이전트(OQ2)를 차단 모드로 전환 — 2인 승인 `agent_promote`. 실행 시 L2/L3 를 요구하는 에이전트는 보류 유지 |
| GET·POST | `/v1/market`, `/v1/market/{id}:request` | 장터(신뢰 등급·라이선스·격리·상태) · 설치 요청(2인 승인 → 등록 심사 R1~R5) |
| GET·POST | `/v1/search`, `/v1/notifications`, `/v1/topology`, `/v1/data-protection` | ⌘K 전역 검색 · 알림 센터 · 배포 토폴로지 · 데이터 보호 현황 |
| GET | `/v1/install/precheck` | 설치 사전 점검·검증 — 배포 형태·DB·마이그레이션·키 주입·수집기·L1·worker·관리자·커버리지 |
| GET | `/v1/setup/status` | 첫 실행 마법사 단계 5개 완료 여부 · 설치 후 경과 · 첫 판정까지 분(목표 30분, NFR-O1) |
| POST | `/v1/setup/verify` | 설치 검증(플랫폼 관리자) — 입력·도구·출력 관문 도달 + 증적 적재, 격리·서명·강등 기본값·누락 검증, 원장 기록 |
| POST | `/v1/profiles/{id}:preview`, `/v1/rogue/{name}:terminate`, `/v1/redteam/campaigns:request` | 판정 미리보기(재생, 저장 없음) · 이탈 에이전트 강제 종료(격리+토큰·신원 폐기) · 레드팀 실행 승인(2인) |
| POST | `/v1/profiles:validate`, `/v1/profiles` | 사용자 정의 프로파일 검증 · 저장(`<tenant>.<id>`) |
| GET | `/v1/findings`, `/v1/findings/{id}` | 판정 조회 (trace·agent·verdict·from) · 상세는 `ruleDescription`·`ruleDescriptionEn` |
| GET·POST | `/v1/approvals`, `/v1/approvals/{id}:decide` | 승인 대기함 · 결정 (승인자 역할, 본인 요청 불가) |
| GET | `/v1/evidence`, `/v1/evidence:verify?chain=`, `/v1/evidence:export?chain=`, `/v1/evidence/public-key` | 원장 조회 · 체인(테넌트)별 검증 · 한 체인 서명 묶음 · 공개키 |
| POST | `/v1/scan` | 상시 점검 즉시 실행 `{artifact:{kind,…}, tenant?, agents?}` — 차단급 발견은 격리 목록에 등록 |
| GET·POST | `/v1/scan-targets`, `/v1/scan-targets/{id}:run` | 점검 대상 등록(주기) · 수동 실행 |
| GET·POST | `/v1/quarantine`, `/v1/quarantine/{id}:release` | 격리 목록(관문이 즉시 참조, `expiresAt`) · 해제(주체 필수). 깊은 검사가 만든 principal·session 격리는 **202 + 2인 승인** |
| GET·POST | `/v1/incidents`, `/v1/incidents/{id}`, `/v1/incidents/{id}:contain`, `:close` | 사건 상관(FR-P06) · 타임라인·그래프·런북(`runbookText` + 영어 `runbookTextEn`, `runbooks/en/`) · 봉쇄·종결 |
| GET·POST | `/v1/risks` | 위험 등록부 (수용은 책임자·기한 필수) |
| GET | `/v1/reports`, `/v1/reports/{framework}?format=json\|md` | 통제 매핑 보고서 — owasp-llm-2026 · owasp-asi-2026 · eu-ai-act · pipa · nist-ai-rmf |
| GET·POST | `/v1/governance/snapshot`, `/v1/governance:assess` | 플랫폼 자체 거버넌스 스냅샷 · D10·X03·X08~X10 점검 |
| GET·POST | `/v1/redteam/campaigns`, `/v1/redteam/campaigns:run` | 상시 레드팀(내부 공격 코퍼스, 주체 필수) |
| GET | `/v1/cards/{agent}` | 시스템 카드(매니페스트 자동 생성) |
| GET | `/health`, `/healthz`, `/readyz` | 운영 |

실제 응답 (local, `tool-agent` 적용 후 출력 관문):

```json
POST /v1/judge:batch {"gate":"output","target":"agent.garam.example","request":{"output":"key sk-ant-api03-…"}}
{
 "gate": "output", "verdict": "transform", "stage": "enforce", "profile": "tool-agent", "policy": "default@v1",
 "agents": ["d1-06", "d1-07", "d2-03", "x05"], "degraded": [], "latencyMs": 0.638, "budgetMs": 150, "overBudget": false,
 "decisions": [{"agent": "d2-03", "ruleId": "D2-03.anthropic-key", "original": "transform", "effective": "transform", "reasons": []}, "…"],
 "transformed": {"field": "output", "value": "key [REDACTED_ANTHROPIC_KEY]"}
}
```

무해화 결과(`transformed`)는 응답에만 실리고 저장되지 않는다. 저장되는 Finding 에는 원문이 없다(`payloadRef: null`, NFR-D1).

## 에이전트

80종 전체 목록·상태는 콘솔 `/catalog` 또는 `GET /v1/agents`, 도식 대응은 `/risk-map`.

| 관문 | 바인딩되는 에이전트 (full-mesh 기준) |
|---|---|
| 입력 (C1, 예산 80ms) | D1-01~05 · D2-04 · D5 6종 · D8-01·02·03·07 · X06 — 17종 |
| 도구 (C2, 예산 20ms) | D3 7종 · D4-03 · D6 7종 · D8-04 · X01 · X04 — 18종 |
| 출력 (C1·C3, 예산 150ms) | D1-06·07 · D2-01·02·03·05 · D4 6종 · X05 — 13종 |
| offline (상시·거버넌스) | D2-06·07 · D5-07 · D7 7종 · D8-05·06 · D9 7종 · D10 7종 · X02·03·07~10 — 32종 |

새 에이전트: `python scripts/new_agent.py <ITEM> <slug> --gate … --engine … --verdicts …` → core·engine·시험 데이터 작성 → `python -m aegis eval <id> --update-baseline`.
서드파티: `python -m aegis bundle <dir> --key k --key-id id` → `POST /v1/agents` (R1~R5 심사).
소형 분류기(D1-01·D1-03 기본 엔진의 두 번째 판정기, OQ4): `python scripts/train_classifier.py [--out 경로]` — 합성 학습셋(`aegis/trainset.py`)·저장소 시험셋으로 재현 가능하게 학습해 `aegis/data/injection-clf-v1.json` 을 쓰고, 마지막 줄 sha256 을 엔진의 `MODEL_SHA256` 에 고정한다(다르면 적재 거부). 공개 코퍼스는 학습에 쓰지 않는다. 규칙 전용 엔진(`spotlight_rules`·`jailbreak_corpus`)은 남아 있어 `/v1/agents/{id}:inspect` 의 `engine` 으로 비교할 수 있다.

## Make 타겟

| 타겟 | 설명 |
|------|------|
| `make <mode>-all / -build / -logs / -stop / -restart / -ps` | 수명주기 (`mode` = local \| prod) |
| `make test` | API·SDK·에이전트 품질 게이트 pytest (local dev 컨테이너) |
| `make test-web` | 콘솔 vitest + tsc |
| `make coverage` | 도식 누락 검증 — 엄격 범위 누락 시 실패 |
| `make admin-token [ENV=] [RESET=1]` | 첫 실행 부트스트랩 토큰(24h, 1회용) — `RESET=1` = 비상 관리자 재발급(원장 기록) |
| `make cli` | 단일 파일 CLI → `dist/aegis-linux-<arch>` (PyInstaller, 리눅스 glibc ≥ 2.36, 파이썬 불필요) |
| `make helm-lint` · `make k8s-rehearsal [KEEP=1]` | 헬름 차트 정적 검증 · 로컬 k3d 설치 리허설(이미지 반입 → install → 스모크 → 롤링 갱신 → 삭제) |
| `make idp-up` · `make idp-down` | 조직 SSO 시험 IdP(Keycloak 26.3, local `idp` 프로파일) — 렐름·시험 사용자(비밀번호·TOTP, 비커밋 `infra/keycloak/import/`) 생성 후 기동 · 중지 |
| `make bao-up` · `make bao-down` | OpenBao 시크릿 백엔드(local `bao` 프로파일, dev 서버) — 루트 토큰(비커밋 `infra/openbao/bao.env`)으로 정책 `aegis-broker`·`aegis-lease-holder`, 토큰 역할 `aegis-lease`, 브로커 토큰(`infra/openbao/api.env`) 구성 후 api·worker 재기동 · 중지하고 내장 브로커로 복귀 |
| `make bao-up MODE=server` · `make bao-unseal` | OpenBao 운영형 — 초기화(키 3·임계 2, 비커밋 `infra/openbao/init.json`)·봉인 해제·감사 장치 확인·정책·브로커 토큰 / 재기동 뒤 봉인 해제(임대는 raft 에 남는다). 봉인 중에는 발급 503·확인 거부 |
| `make corpus-eval` | 공개 공격 코퍼스 실측(NFR-Q2) — JailbreakBench·garak(주입·탈옥) + HarmBench·XSTest 위험(유해 요청, 참고) + XSTest 안전·GSM8K(정상 오탐) 를 규칙 전용 vs 이중 판정(+ deep·model) × 직접·간접으로 재생 → 원장·`/observability/slo`·성공 지표. 해시 불일치면 실행 안 함, 페이로드 미보존, 분류기 학습에 쓰지 않음. worker 가 주 1회 반복. `VARIANTS=dual,model MODES=direct` 로 일부만 |
| `make db-backup ENV=prod` | 기본 백업 즉시 1회 + 목록(pg_basebackup tar·gzip·WAL 포함, 최근 `DB_BACKUP_KEEP` 개, 오래된 보관 WAL 정리) |
| `make db-restore-drill ENV=prod` | 복구 훈련 — 원장 머리 기준점 → WAL 전환·보관 대기 → 전용 볼륨에 최신(또는 `DRILL_BACKUP=<이름>`) 기본 백업 + WAL 재생·승격 → 원장 전체 검증·기준점 확인 → RTO 를 원장(kind=dr)에 기록. `KEEP=1` 이면 훈련 서버 유지 |
| `make db-restore-drill ENV=prod SOURCE=offsite` · `make db-offsite ENV=prod` | 객체 저장의 암호화 복사본만으로 복구 훈련(받기·복호화·검증 → 복원·재생 → 원장 검증) / 외부 복사 즉시 1회 + 상태 |
| `make db-failover-drill ENV=prod CONFIRM=1` | 장애 조치 훈련 — 대기 서버 정지 중 원장 커밋 대기 확인 → 원장 20건 응답 직후 주 서버 일시 정지 → 대기 서버 승격·마지막 응답 머리 확인(원장 RPO 0) → 주 서버 재개·대기 서버 재복제·동기 재등록 |
| `make db-sync ENV=prod MODE=on\|off` | 원장 동기 복제 켜기/끄기(재시작 없음) — 대기 서버 장기 장애 때 off 로 원장 커밋 대기 해제(RPO 0 해제), 복구 뒤 on |
| `make certs-rotate ENV=prod` | 내부 말단 인증서 즉시 재발급(CA 유지) → PG 설정 재적재 · api SIGHUP(작업 프로세스를 하나씩 교체) · web·수집기·worker 는 다음 연결부터 — 재기동 없음(부하 중 오류 0, 48차) |
| `make certs-client ENV=prod NAME=<이름>` | 외부 도구·ingress·SDK 용 클라이언트 인증서 묶음 → `infra/tls/clients/<이름>/`(비커밋). prod API 호출 예: `curl --cacert …/ca.crt --cert …/tls.crt --key …/tls.key https://localhost:8000/health` |
| `make kms-rewrap [ENV=] [ROTATE=1]` | 저장 암호화(NFR-D2) — 수정 가능한 표(정책·프로파일·발견·승인·결정 사유·표본·OTP 비밀)와 서명 키·세션 비밀 파일을 현재 KEK·새 DEK 로 다시 암호화(옛 평문 포함). `ROTATE=1` 이면 builtin KEK 새 버전 먼저. 원장은 추가 전용이라 제외(옛 KEK 는 복호화 전용으로 남김) |
| `make bao-rotate-kek [MODE=server]` | OpenBao transit 저장 암호화 KEK(`aegis-kek`) 회전 — 루트 토큰(구성 전용)으로, 브로커 토큰은 포장·해제만 |
| `make guard-up [ENV=prod]` · `make guard-down` | D1-03 깊은 검사 켜기·끄기 — guard 기동 → `infra/guard/api.env`(GUARD_URL, 비커밋) → api·worker 재생성. 켜면 `make corpus-eval` 에 deep 변형이 더해진다 |
| `make agw-up` · `make agw-down` | agentgateway MCP 게이트웨이(Epic 67, local) — 서비스 계정 `svc.agentgateway` 토큰(24시간, 비커밋 `infra/agentgateway/extmcp.env`)·`agw.demo` 에 tool-agent 적용 → extmcp·시연 MCP·agentgateway 기동. MCP 클라이언트는 `http://127.0.0.1:3100/mcp`, 주체는 `x-aegis-principal` 헤더 |
| `make l2-up [ENV=prod]` · `make l2-down` | L2 격리 켜기·끄기(Epic 65) — sandbox-l2 빌드·기동(runsc 고정 판, 준비 = 실제 샌드박스 커널 gVisor) → `infra/gvisor/api.env`(SANDBOX_L2_URL, 비커밋) → api·worker 재생성. 끄면 L2 요구 에이전트는 다시 보류(격리 강등 금지). 샌드박스 루트 FS 는 빌드 시점 사본 — 코드를 바꾸면 다시 l2-up |
| `make injguard-up [ENV=prod]` · `make injguard-down` | D1-03 인라인 주입 분류 모델 켜기·끄기(Epic 64) — injguard 기동 → `infra/injguard/api.env`(INJGUARD_URL · `ENGINE_OVERRIDES=d1-03=injection_model`, 비커밋) → api·worker 재생성. 켜면 `make corpus-eval` 에 model 변형이 더해진다 |
| `make bao-hsm-up` · `make bao-hsm-status` · `make bao-hsm-down` | OpenBao HSM 봉인 리허설(Epic 68, prod 프로파일 bao-hsm) — OpenBao 2.4.1+hsm(cgo) + SoftHSM2: 토큰 AegisMesh·RSA-3072 비추출 키(비커밋 PIN `hsm.env`·SO PIN `hsm-so.pin`) → `seal "pkcs11"`(OAEP) 단일 raft 노드 → 초기화(복구 키 3/2, 비커밋 `hsm-init.json`)·점검 비밀 / 봉인 방식·상태·점검 비밀 읽기 / 중지(볼륨 유지). 재기동하면 사람 없이 ~1 s 에 봉인 해제, PIN·HSM 이 없으면 기동 거부 |
| `make bao-cluster-up ENV=prod` · `make bao-cluster-unseal` · `make bao-cluster-status` · `make bao-cluster-down` | OpenBao 운영 마감 리허설(Epic 56, prod) — 봉인 해제기(Shamir 3/2, 비커밋 `unsealer-init.json`)·transit `aegis-autounseal`·포장 전용 토큰(`cluster.env`) → bao-1~3 raft(retry_join·자동 봉인 해제·TLS 1.3 상호 인증) → bao-1 초기화(복구 키, `cluster-init.json`) → api·worker 가 3주소·상호 TLS(`cluster-api.env`) / 봉인 해제기 재기동 뒤 봉인 해제(노드는 스스로) / 노드별 봉인·리더·투표자 / 중지·내장 브로커 복귀 |
| `make bus-up [ENV=prod]` · `make bus-down` · `make bus-tail [DURABLE=siem] [MAX=20]` | 발견 버스(Epic 60) — NATS 2.11.9 JetStream(스트림 AEGIS) + bus-relay(원장 커서 → 비허용 발견·사건·인증 보안 이벤트 요약 게시, 최소 1회·Nats-Msg-Id 중복 제거). prod 는 상호 TLS. `BUS_URL` 은 비커밋 `infra/nats/api.env` · SIEM 소비 예 = 지속 소비자 |
| `make garak-scan [OUT=test/impl/<N>/logs] [GARAK_PROBES=…]` | 외부 레드팀 엔진 garak 0.13.1(Epic 59, local `garak` 프로파일) — 같은 탐침을 무방비 모델(되풀이)과 AegisMesh 관문 뒤 모델(garak-target, 서비스 계정 토큰은 비커밋 `infra/garak/target.env`)에 → 원장 quality `garak_scan`(탐침별 공격 성공률), SLO 화면 |
| `make mirror-push` · `make k8s-mirror-rehearsal [KEEP=1]` | 폐쇄망 레지스트리 미러(Epic 61) — compose `registry`(127.0.0.1:5005, 프로파일 mirror)에 이미지(`infra/mirror/images.txt`, 노드 아키텍처·digest 고정)·헬름 차트(OCI)를 올리고, k3d 를 docker.io = 미러·원 경로 끔으로 만들어 OCI 차트로 설치 → 스모크 → 롤링 → 삭제 |
| `make pins-refresh` | 고정 판 갱신(Epic 58) — 이미지 빌드(`pins` 스테이지) 안에서 DB-IP 최신 월·sha256, MDS3 다음 판(nextUpdate 지남)을 정해 Dockerfile 맨 위 전역 ARG 를 고친다 → diff 확인 후 재빌드. worker 가 매일 낡음 점검(알림 '고정 판', `GET /v1/updates` 의 `pins`) |
| `make ledger-rewrap [ENV=prod] [VACUUM=1]` | 원장 저장 재암호화 실행(Epic 57) — 2인 승인으로 열린 창 안의 평문 기록을 묶음 암호화(worker 와 함께 돌아도 나눠 처리). `VACUUM=1` = PG `VACUUM FULL evidence`(옛 행 판까지 파일에서 제거) |
| `make spire-up [ENV=prod]` · `make spire-down` | SPIRE 켜기·끄기 — 신뢰 번들·노드 토큰 → `infra/spire/api.env`(IDENTITY_BACKEND=spire, 비커밋) → api·worker → agent → 신원 87개를 등록 항목으로 동기화. 끄면 SPIRE 가 발급한 토큰은 거부(검증 키 없음) |
| `make contract-update` | OpenAPI 계약 스냅샷 갱신(`test/contract/openapi.snapshot.json`) — 의도한 API 변경 뒤, diff 리뷰 |
| `make e2e-passkey OUT=test/impl/<N>/logs` | 패스키·DPoP E2E — Playwright Chromium + CDP 가상 인증기(local `e2e` 프로파일, 콘솔 네트워크 공유): 등록 → 2단계 로그인 → 새 위치 재인증 → OTP → 탈취 토큰 재사용 → 전체 폐기·사건 |
| `make e2e-a11y OUT=test/impl/<N>/logs [ONLY=/a,/b]` | 접근성 점검(ONLY = 시작 경로, 동적 링크는 따라감) — axe-core 4.10(WCAG 2.2 AA 태그) + 키보드(본문 바로가기·초점 표시·초점 가림)·로그인 입력 목적. 콘솔 경로 전부(page.tsx)를 ko·en 으로, 동적 경로는 목록 링크로 실제 ID 를 찾아 점검. 판정 = serious·critical 0 (local `e2e` 프로파일) |
| `make loadtest [ENV=prod] [DURATION=20] [CONC=64] [PROCS=4] [MIX=input:4,tool:3,output:2,stream:1] [LABEL=] [UNIQUE=1]` | 판정 부하 측정 — 관문별 rps·p50/p95/p99·관문 실행 p95 (서비스 계정·대상 load.test 준비, 원장 기록). UNIQUE=1 = 입력마다 무작위 꼬리(모델 엔진 캐시를 비켜 실제 모델 호출) |
| `make db-ping / db-migrate / db-seed [ENV=]` | DB |
| `make db-shell ENV=prod` · `make db-reset / db-fresh` (local 전용) | DB |
| `make shell [ENV=]` · `make deploy` · `make preflight` · `make help` | 기타 |

## 환경 변수

| 변수 | local | prod | 설명 |
|------|-------|------|------|
| `APP_ENV` | `local` | `prod` | |
| `API_PORT` / `WEB_PORT` / `BIND_HOST` | 8000 / 3000 / 127.0.0.1 | 동일 | 게시 포트 |
| `DB_ENGINE` / `DATABASE_URL` | sqlite / SQLite 파일 | postgres / `db` 접속 문자열 | |
| `DB_USER` / `DB_PASSWORD` / `DB_NAME` | — | CHANGE_ME → 주입 | |
| `AUTO_MIGRATE` | `true` | `false` | 기동 시 alembic upgrade + seed |
| `LEDGER_SIGNING_KEY` | (없음 → 볼륨에 생성) | CHANGE_ME → KMS 주입 | base64 Ed25519 개인키 32바이트 |
| `LEDGER_CHECKPOINT_EVERY` | 100 | 100 | N 건마다 서명 체크포인트 |
| `AEGIS_TIMEOUT_FACTOR` | (4) | (4) | 관문 하드 타임아웃 = p95 예산 × 계수 |
| `AEGIS_RUNTIME_ISOLATION` | (L0) | (L0) | 런타임 제공 격리 등급 — 미달 에이전트는 기동 거부 |
| `AEGIS_COVERAGE_STAGE` | (5) | (5) | 누락 검증 엄격 범위 로드맵 단계 |
| `WORKER_INTERVAL_SEC` | 30 | 30 | 상시 점검 worker 주기 |
| `REGISTRY_DIR` | /app/data/registry | 동일 | 심사 통과 서드파티 번들 저장 |
| `REVIEW_CPU_SEC` | 20 | 20 | 등록 심사 R4 재생 CPU 한도(메모리 768MB 고정) |
| `EVIDENCE_RETENTION_DAYS` | 90 | 90 (regulated-kr 이면 1825) | 증적 온라인 보존 — 부족하면 D10-02 차단 |
| `MODEL_EGRESS` | deny | deny | 외부 모델 호출 정책(NFR-D5) |
| `OTEL_ENDPOINT` | http://otel-collector:4318 | 동일 | OTLP/HTTP 수집기 — 미설정이면 내보내기 없음 + D10-07 경보 |
| `OTEL_ALLOW_TRACE_RATIO` | 1.0 | 0.1 | allow 판정 추적(span) 표본 비율 — 비허용·강등·예산 초과 판정은 항상, 지표는 표본 없이 전부(Epic 66) |
| `OTEL_DEBUG_VERBOSITY` | detailed | basic | 수집기 debug 내보내기 상세도 |
| `SPIFFE_TRUST_DOMAIN` / `SVID_TTL_SEC` | aegismesh.local / 3600 | 동일 | 워크로드 신원 신뢰 도메인 · SVID 수명(50% 회전) |
| `SVID_SIGNING_KEY` | (없음 → 볼륨에 생성) | CHANGE_ME → KMS 주입 | base64 Ed25519 SVID 발급 키 |
| `SECRET_LEASE_MAX_SEC` | 900 | 900 | 동적 시크릿 최대 수명(갱신 포함) |
| `SECRETS_BACKEND` / `OPENBAO_ADDR` / `OPENBAO_TOKEN` | builtin / http://bao:8200 / (비움 — `make bao-up` 이 덮어씀) | builtin / CHANGE_ME / CHANGE_ME | 동적 시크릿 임대 엔진 · OpenBao 주소(쉼표로 여러 노드 — 연결 실패·봉인·리다이렉트면 다음 노드) · 브로커 토큰(정책 aegis-broker — 루트 토큰 금지) |
| `OPENBAO_CA_FILE` / `OPENBAO_CLIENT_CERT` / `OPENBAO_CLIENT_KEY` | (빈 값) | (빈 값 — `make bao-cluster-up` 이 /tls 로) | OpenBao 상호 TLS(Epic 56) — 내부 CA·클라이언트 인증서(파일이 바뀌면 다시 읽음) |
| `SANDBOX_L1_SLOTS` / `SANDBOX_QUEUE_SEC` / `SANDBOX_RECYCLE_USES` | 4 / 2 / 200 | 동일 | L1 동시 슬롯 · 풀 고갈 대기 후 거부 · 웜 하위 프로세스 회수 주기 |
| `SANDBOX_CALL_TIMEOUT_SEC` / `SANDBOX_CPU_SEC` | 2 / 60 | 동일 | 경로 밖 판정 시간 한도 · 웜 하위 프로세스 누적 CPU 한도 |
| `GOVERNANCE_INTERVAL_SEC` / `REDTEAM_INTERVAL_SEC` | 3600 / 86400 | 동일 | worker 주기 작업 |
| `AUTH_SECRET` | (없음 → 볼륨에 생성) | CHANGE_ME → 주입 | 세션·API 토큰 HMAC 서명 비밀 |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` | (없음) | (없음) | 조직 SSO 초기값 — 콘솔 /admin/sso 에서 저장하면 DB 설정 우선 |
| `OIDC_CLIENT_SECRET` | (없음) | (없음) | 기밀 클라이언트일 때만(기본 공개 클라이언트 + PKCE) — DB 에 두지 않음 |
| `OIDC_BACKCHANNEL_MAP` | `http://localhost:8080=http://keycloak:8080` | (없음) | 서버 간 IdP 호출 주소 치환(브라우저 주소 ≠ 컨테이너 주소) |
| `IDP_PORT` | 8080 | — | 시험 IdP(Keycloak) 호스트 포트 (`make idp-up`) |
| `BAO_PORT` | 8210 | — | 시험 OpenBao 호스트 포트 (`make bao-up`) |
| `CORPORA_DIR` / `CORPUS_INTERVAL_SEC` | /corpora / 604800 | /corpora / 604800 | 공개 코퍼스 반입본 경로(없으면 정기 실측 건너뜀) · 정기 실측 주기(주 1회) |
| `EVIDENCE_ASYNC` / `EVIDENCE_QUEUE_MAX` / `EVIDENCE_SAMPLE_EVERY` / `EVIDENCE_BATCH_MAX` | true / 20000 / 10 / 500 | 같음 | 인라인 판정 증적 비동기 묶음 적재 — 대기열 80% 이상이면 allow 판정 1/N 표본(원장·알림 기록), 50% 이하 복귀 |
| `HOT_CACHE_TTL_SEC` | 2 | 2 | 바인딩 조회 캐시(같은 프로세스 쓰기는 즉시 무효화, 0 = 끔) — NFR-O4 10초 안 |
| `FP_BUDGET_MIN` / `FP_RECOVER_DAYS` / `QUALITY_CHECK_INTERVAL_SEC` / `GOLDEN_INTERVAL_SEC` | 2 / 7 / 300 / 604800 | 같음 | 오탐 예산 최소 건수·강등 후 복귀 기간·worker 예산 점검 주기·골든셋 재생 주기(주간) |
| `WEB_CONCURRENCY` | — (reload) | 2 | api 작업 프로세스 수 (prod compose 는 셸 값 우선) |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` / `DB_MAX_CONNECTIONS` | 10 / 10 / — | 10 / 10 / 300 | 작업 × (풀+초과) ≤ PostgreSQL max_connections |
| `DB_REPLICATION_PASSWORD` | — | `CHANGE_ME` | 복제 역할(replicator) 비밀번호 — 대기 서버·기본 백업이 쓴다 |
| `DB_ARCHIVE_TIMEOUT_SEC` / `DB_BACKUP_INTERVAL_SEC` / `DB_BACKUP_KEEP` | — | 60 / 14400 / 12 | WAL 세그먼트 강제 전환 주기(일반 데이터 RPO 상한) · 기본 백업 주기(WAL 재생 시간 < RTO 가 되게: 실측 최대 WAL 7 MB/s·재생 65 MB/s → 4시간) · 보관 개수 |
| `TLS_DIR` | (빈 값 = 평문) | `/tls` | 내부 상호 TLS 인증서(ca.crt·tls.crt·tls.key). prod 는 `OTEL_ENDPOINT=https://otel-collector:4318`, libpq `PGSSLMODE=verify-full` 등은 compose 가 넣는다 |
| `KMS_BACKEND` / `KMS_TRANSIT_KEY` | builtin / aegis-kek | builtin / aegis-kek | 저장 암호화 KEK 위임처 — builtin(데이터 디렉터리 키 고리 `kms_keyring.json`, 비커밋) · openbao(transit 키, **영속 OpenBao 만** — dev 서버는 재기동 때 키를 잃는다). 백엔드를 바꿔도 옛 값은 포장 접두사로 열린다 |
| `GUARD_URL` / `GUARD_UNSAFE_MIN` / `GUARD_QUEUE_MAX` / `GUARD_THREADS` | (빈 값) / 0.5 / 200 / 8 | 같음 | 깊은 검사 모델 주소(`make guard-up` 이 넣음) · 위험 확률 하한 · 대기 상한(넘치면 건너뛰고 센다) · 모델 CPU 스레드 |
| `GUARD_QUARANTINE_SEC` | 3600 | 3600 | 깊은 검사 경보 → 같은 주체·세션 격리 기한(초, 0 = 경보만). 해제는 2인 승인 |
| `S3_ENDPOINT` / `S3_BUCKET` / `S3_ACCESS_KEY` / `S3_SECRET_KEY` / `OFFSITE_INTERVAL_SEC` | (빈 값) / aegis-backup / — / — / 60 | https://objstore:8333 / aegis-backup / `CHANGE_ME` / `CHANGE_ME` / 60 | 백업 외부 복사 대상(S3 호환, 상호 TLS)·자격 증명(버킷 하나로 한정)·복사 주기. 호스트 상실 RPO 상한 ≈ archive_timeout + 이 값 |
| `GEO_SAME_PLACE_KM` / `GEO_TRAVEL_MAX_KMH` / `GEO_TRAVEL_MIN_KM` | 100 / 900 / 500 | 같음 | 지오 IP(Epic 55) — 같은 나라 이 거리 안 = 같은 위치(대도시권 망 전환은 재인증 안 함) · 불가능한 이동 속도·최소 거리(재인증·D5-03 경보) |
| `BUS_URL` / `BUS_START` / `BUS_MAX_AGE_DAYS` | (빈 값 — `make bus-up` 이 넣음) / head / 7 | 같음(prod 는 tls://nats:4222 + BUS_CA_FILE·BUS_CLIENT_CERT·BUS_CLIENT_KEY) | 발견 버스(Epic 60) — NATS 주소 · 첫 기동 커서(head = 지금부터, all = 원장 처음부터) · 스트림 보존 일수 |
| `INJGUARD_URL` / `INJGUARD_WINDOW` / `INJGUARD_TIMEOUT_MS` / `INJGUARD_ALERT` / `INJGUARD_BLOCK` | (빈 값) / 96 / 60 / 0.95 / 0.999 | 같음(prod 주소 https) | 인라인 주입 모델(Epic 64) — 주소(`make injguard-up` 이 넣음) · 앞·뒤 토큰 창 · 응답 기다림 상한(넘으면 이중 판정) · 경보·차단 확률 |
| `SANDBOX_L2_URL` / `SANDBOX_L2_SLOTS` | (빈 값) / 4 | 같음(prod 주소 https) | L2 격리 브로커 주소(`make l2-up` 이 넣음, 비면 L2 없음) · 브로커 동시 샌드박스 슬롯 |
| `ENGINE_OVERRIDES` | (빈 값) | (빈 값) | 에이전트 기본 엔진 바꾸기 `agent=engine,…` — `make injguard-up` 이 `d1-03=injection_model`. 매니페스트에 없는 엔진은 무시 |
| `LEDGER_REWRAP_WINDOW_SEC` | 21600 | 21600 | 원장 재암호화 창 수명(Epic 57) — 2인 승인 뒤 이 시간 안에만 DB 트리거가 평문 → 암호문 갱신 허용 |
| `FIDO_MDS_OPTIONAL` | 0 | 0 | 이미지 빌드 스위치(Epic 54) — 1 이면 MDS3 받기 실패(요청 제한 등) 때 스냅숏 없이 빌드(허용목록 테넌트 보안 키 등록은 닫힌 실패). 받은 스냅숏의 검증 실패는 항상 빌드 실패 |
| `IDENTITY_BACKEND` | builtin | builtin | 워크로드 신원 발급처 builtin(내장 Ed25519) · spire(Workload API·ES256, `make spire-up` 이 넣음). 검증은 전환 중 두 서명 모두 받음 |
| `TENANCY_TEST_INTERVAL_SEC` | 86400 | 86400 | worker 테넌트 교차 접근 시험 주기 |
| `FAIRNESS_INTERVAL_SEC` | 604800 | 604800 | worker 공정성 정례 측정 주기(주 1회, 적용 중인 보호 대상마다) |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGINS` | localhost / http://localhost:3000 | CHANGE_ME (콘솔 도메인 / https 주소) | 패스키 RP ID·허용 origin — 다른 도메인 자격증명·origin 거부 |
| `WEB_SESSION_SECRET` (web) | (비움 → `.next/cache/aegis-web-secret` 생성) | CHANGE_ME → 주입 | 콘솔이 세션별 DPoP 키를 봉인하는 비밀 — 콘솔 인스턴스가 여러 개면 같은 값 필수 |
| `APPROVAL_TTL_MIN` | 240 | 240 | 승인 요청 만료(분) — worker 가 만료 시 자동 거절, 만료 후 결정 409 |

> `.env.prod` 는 커밋하지 않는다. `.env.local` 은 시크릿이 없어 커밋한다(CI).

## 시험

`test/` 단일 트리 — `test/dev-env/`(환경 검증), `test/impl/<Nth>/`(구현 차수별 시나리오·결과). 원본 로그 `logs/` 는 비커밋.

| 차수 | 범위 | 판정 |
|---|---|---|
| [dev-env](test/dev-env/result.md) | 표준 환경 (local·prod 리허설) | PASS 8/8 |
| [1st](test/impl/1st/result.md) | Epic 1 에이전트 SDK·CLI·MCP | PASS |
| [2nd](test/impl/2nd/result.md) | Epic 2 레지스트리·데이터 (SQLite·PostgreSQL) | PASS |
| [3rd](test/impl/3rd/result.md) | Epic 3 관문·오케스트레이션·정책·프로파일 | PASS |
| [4th](test/impl/4th/result.md) | Epic 4 증적 원장·2인 승인 | PASS |
| [5th](test/impl/5th/result.md) | Epic 5 1단계 P0 에이전트 19종 | PASS |
| [6th](test/impl/6th/result.md) | Epic 6 콘솔 + prod 회귀 | PASS |
| [7th](test/impl/7th/result.md) | Epic 7 2단계 에이전트 22종 | PASS |
| [8th](test/impl/8th/result.md) | Epic 8 상시 점검·worker·격리 | PASS |
| [9th](test/impl/9th/result.md) | Epic 9 3단계 에이전트 26종 | PASS |
| [10th](test/impl/10th/result.md) | Epic 10 등록 심사 R2~R5 | PASS |
| [11th](test/impl/11th/result.md) | Epic 11 거버넌스 11종·보고서·사건·레드팀 (80/80) | PASS |
| [12th](test/impl/12th/result.md) | Epic 12 콘솔 확장 + 실제 브라우저 E2E + prod 회귀 | PASS |
| [13th](test/impl/13th/result.md) | Epic 13 다중 테넌시·사용자·역할·로그인 (PG RLS) | PASS |
| [14th](test/impl/14th/result.md) | Epic 14 정책·관문 관리 (시험 게이트·시뮬레이터·롤백) | PASS |
| [15th](test/impl/15th/result.md) | Epic 15 관측 OTel (수집 단계 마스킹) | PASS |
| [16th](test/impl/16th/result.md) | Epic 16 워크로드 신원·동적 시크릿 | PASS |
| [17th](test/impl/17th/result.md) | Epic 17 샌드박스 브로커 (L1 Landlock·seccomp) | PASS |
| [18th](test/impl/18th/result.md) | Epic 18 폐쇄망 번들·신뢰 저장소·장터 | PASS |
| [19th](test/impl/19th/result.md) | Epic 19 콘솔 잔여 화면 + 45 경로 스윕(local·prod) + prod 완료 게이트 | PASS |
| [20th](test/impl/20th/result.md) | Epic 20 헬름 차트·k3d 설치 리허설·단일 파일 CLI | PASS |
| [21st](test/impl/21st/result.md) | Epic 21 첫 실행 마법사 ②~⑤ + 설치 검증 | PASS |
| [22nd](test/impl/22nd/result.md) | Epic 22 조직 SSO (Keycloak 실 IdP E2E) | PASS |
| [23rd](test/impl/23rd/result.md) | Epic 23 인라인 성능·증적 비동기·스트리밍 (실측 103→374 rps, 16 작업 1,776 rps) | PASS |
| [24th](test/impl/24th/result.md) | Epic 24 판정 이의·오탐 예산·골든셋 1만·코퍼스 미탐률 | PASS |
| [25th](test/impl/25th/result.md) | Epic 25 A2A v1.0 어댑터 (단일 파일 CLI 두 컨테이너) | PASS |
| [26th](test/impl/26th/result.md) | Epic 26 콘솔 본문·보고서 영어 + prod 완료 게이트 | PASS |
| [27th](test/impl/27th/result.md) | Epic 27 에이전트 설정(정책 agentParams)·관문 상세·강등·재배치 | PASS |
| [28th](test/impl/28th/result.md) | Epic 28 D1·D2 상세 화면 (삭제 전파·재현 시험) | PASS |
| [29th](test/impl/29th/result.md) | Epic 29 D3·D4 상세 화면 (도구 호출·근거성) | PASS |
| [30th](test/impl/30th/result.md) | Epic 30 D5·D6 상세 화면 (신원·토큰·인가·자율·지출) | PASS |
| [31st](test/impl/31st/result.md) | Epic 31 D7·D8·D9 상세 화면 (공급망·메모리·인프라, SBOM CLI) | PASS |
| [32nd](test/impl/32nd/result.md) | Epic 32 작업 흐름 (즉시 사용 마법사·승인 결정·트레이·런북·업데이트) | PASS |
| [33rd](test/impl/33rd/result.md) | Epic 33 공정성 지표·시스템·모델 카드 (P2) | PASS |
| [34th](test/impl/34th/result.md) | Epic 34 로그인 보안 (패스키·OTP·DPoP·재인증·탈취 대응) + Playwright 가상 인증기 E2E + prod 완료 게이트 | PASS |
| [35th](test/impl/35th/result.md) | Epic 35 성공 지표 대시보드 (12종·단계 목표·일 스냅샷) | PASS |
| [36th](test/impl/36th/result.md) | Epic 36 실제 트래픽 미리보기 (옵트인·2인·마스킹 표본·라벨) | PASS |
| [37th](test/impl/37th/result.md) | Epic 37 증적 보존기한 만료 배치 + OpenAPI 계약 시험 | PASS |
| [38th](test/impl/38th/result.md) | Epic 38 로그인·등록 정책 (2단계 강제·AAGUID·IdP 로그아웃·L1 대체 경보 전용·차단 전환) | PASS |
| [39th](test/impl/39th/result.md) | Epic 39 접근성 AA 점검·수정 (axe-core 전 경로 ko·en 위반 0, 키보드) | PASS |
| [40th](test/impl/40th/result.md) | Epic 40 영어 런북·규칙 설명 · en 사건·카탈로그·판정 화면 한글 0 | PASS |
| [41st](test/impl/41st/result.md) | Epic 41 OpenBao 시크릿 백엔드 (발급·갱신 상한·회수·만료·장애 거부) + prod 완료 게이트 | PASS |
| [42nd](test/impl/42nd/result.md) | Epic 42 소형 분류기 이중 판정 (D1-01·D1-03, 무결성 고정·재현성) | PASS |
| [43rd](test/impl/43rd/result.md) | Epic 43 공개 공격 코퍼스 실측 — 측정 체계 PASS, 미탐 41.1% 로 NFR-Q2 미달(보고) | PASS |
| [44th](test/impl/44th/result.md) | Epic 44 영어 마무리 — en 도메인 상세 화면 한글 0 | PASS |
| [45th](test/impl/45th/result.md) | Epic 45 확대·재배치 접근성 (320px·글자 간격·글자 200%) | PASS |
| [46th](test/impl/46th/result.md) | Epic 46 OpenBao 운영형 리허설 (raft·봉인 해제·감사) + prod 완료 게이트 | PASS |
| [47th](test/impl/47th/result.md) | Epic 47 백업·복구·동기 복제 (NFR-A5 — 복구 RTO 45~59 s·장애 조치 38 s·원장 RPO 0) | PASS |
| [48th](test/impl/48th/result.md) | Epic 48 내부 상호 TLS (NFR-D3 — 4구간·평문 거부·부하 중 무중단 회전) | PASS |
| [49th](test/impl/49th/result.md) | Epic 49 저장 암호화 (NFR-D2 — OpenBao transit·builtin, 덤프·WAL·백업 평문 0, 108만 행 재암호화) | PASS |
| [50th](test/impl/50th/result.md) | Epic 50 유해 요청 포장 탐지 (OQ9 — 검증된 안전 분류 모델 응답 뒤 깊은 검사, 미탐 41.1% → 9.7%) + 8차 완료 게이트 | PASS |
| [51st](test/impl/51st/result.md) | Epic 51 깊은 검사 실효화 (부하 210 rps 선별 대기열 — 주입 경보 75%·선입선출 0.12%, 경보 → 주체·세션 격리 다음 요청 30/30 차단, 해제 2인) | PASS |
| [52nd](test/impl/52nd/result.md) | Epic 52 백업 외부 복사 (SeaweedFS S3·상호 TLS·KMS 봉투 암호화 18.2 GB, 평문 0, 객체 저장만으로 복구 RTO 93 s) | PASS |
| [53rd](test/impl/53rd/result.md) | Epic 53 SPIRE 연동 (신원 87 = 등록 항목 87, ES256 발급·검증·즉시 회전·폐기, builtin 복귀) | PASS |
| [54th](test/impl/54th/result.md) | Epic 54 보안 키 증명 체인 (FIDO MDS3 no 290 고정 판·R3 서명 체인·CRL, 변조 5종 빌드 실패, 허용목록 AAGUID 라도 체인 없으면 거부 — E2E 7/7) | PASS |
| [55th](test/impl/55th/result.md) | Epic 55 지오 IP·불가능한 이동 (DB-IP Lite 고정 판, 실제 DB 콘솔 E2E 14/14 — 대도시권 통과·✈ 9,080 km/수 초 → 재인증·경보) | PASS |
| [56th](test/impl/56th/result.md) | Epic 56 OpenBao 3노드 raft·transit 자동 봉인 해제·TLS 1.3 상호 인증(리더 장애 중 임대 실패 0) + CLI 한/영 + 9차 완료 게이트 | PASS |
| [57th](test/impl/57th/result.md) | Epic 57 원장 평문 제거 — 2인 승인 창 재암호화 1,340,973 → 0, 전체 검증 1,601,483건 OK, VACUUM FULL 뒤 데이터 파일 평문 0 | PASS |
| [58th](test/impl/58th/result.md) | Epic 58 고정 판 갱신 `make pins-refresh`(이미지 빌드 안에서 다음 DB-IP·MDS3 판) · 실행 중 낡음 알림 | PASS |
| [59th](test/impl/59th/result.md) | Epic 59 garak 0.13.1 어댑터 — 같은 탐침 무방비 45.3% → 관문 뒤 24.7% | PASS |
| [60th](test/impl/60th/result.md) | Epic 60 발견 버스 NATS JetStream — 누락 0·중복 0·재기동 재생, prod 상호 TLS | PASS |
| [61st](test/impl/61st/result.md) | Epic 61 폐쇄망 레지스트리 미러 — 미러만으로 k3s 설치 43 s, 원 경로 없음 확인 | PASS |
| [62nd](test/impl/62nd/result.md) | Epic 62 TPM·android-key 증명 형식 — 거부 사유 11종 | PASS |
| [63rd](test/impl/63rd/result.md) | Epic 63 보조기술 점검(랜드마크·제목·이름·lang) + 동적 오류 role=alert 22곳 | PASS |
| [64th](test/impl/64th/result.md) | Epic 64 인라인 주입 모델(deberta-v3 v2 ONNX) — 직접 주입 미탐 41.1% → 22.5%, 오탐 그대로, 한국어는 모델 생략 | PASS |
| [65th](test/impl/65th/result.md) | Epic 65 L2 격리 gVisor — L2 요구 에이전트 심사·판정을 샌드박스에서, 탈출 23/23·우회 6/6 막힘 | PASS |
| [66th](test/impl/66th/result.md) | Epic 66 노드당 2,000 rps — 병목 3개 해결(사건 행 잠금·요청당 SQL 8→3·추적 표본), 최고 1,797 rps, 공유 VM 에서 목표 미확인 → 결정: 리허설 값 수용 | DONE(목표 미달 기록) |
| [67th](test/impl/67th/result.md) | Epic 67 agentgateway v1.6.0 — MCP tools/call → 도구 관문(차단·승인)·출력 관문(무해화), failClosed | PASS |
| [68th](test/impl/68th/result.md) | Epic 68 HSM 봉인 해제(SoftHSM2 PKCS#11) — 무인 1.0~1.2 s, PIN·HSM 없으면 기동 거부 + 10차 완료 게이트 | PASS |

현재(10차): `make test` 482 passed · `make test-web` 18 passed + tsc · `make e2e-a11y` 전 경로 ko·en 254쪽 axe serious·critical 0 · 재배치·간격·200% 128/128 · 보조기술 4종(랜드마크·제목·이름·lang) 통과 · en 한글 0 · API 계약 227 작업 · 원장 평문 0(전체 검증 554만 건) · 인라인 주입 모델 직접 주입 미탐 22.5% · garak 관문 뒤 공격 성공률 24.7% · L2 gVisor 탈출 23/23 막힘 · MCP 게이트웨이 차단·승인·무해화·failClosed · HSM 무인 봉인 해제 ~1 s · prod 회귀(PG 0023·injguard·L2 상호 TLS·bao-hsm) 통과 · 노드당 처리량 최고 1,797 rps(공유 VM — 리허설 값으로 수용, 2,000 확인은 전용 노드).

9차: `make test` 456 passed · `make test-web` 17 passed + tsc · `make e2e-passkey` 15/15 · 보안 키 증명 E2E 7/7 · 지오 IP E2E 14/14 · `make e2e-a11y` 전 경로 ko·en 254쪽 axe serious·critical 0 · 키보드·인증 53/53 · 재배치 320px·글자 간격·글자 200% 128/128 · en 사건·카탈로그·판정·도메인 상세 한글 0 · OpenBao 3노드 자동 봉인 해제 ≈1 s·리더 장애 중 임대 실패 0 · API 계약 223 작업 · prod 회귀(PG 0021·MDS3·지오·OpenBao 클러스터·외부 복사·SPIRE) 통과. 8차까지: `make corpus-eval` 공개 코퍼스 주입·탈옥 미탐 인라인 41.1% · 응답 뒤 깊은 검사 포함 9.7%(NFR-Q2 충족) · OpenBao dev·운영형 E2E(임대·transit KMS) · 복구 훈련 RTO 38~138 s·원장 RPO 0 · 내부 상호 TLS 4구간 · 덤프·WAL·백업 평문 0 · API 계약 221 작업 · prod 회귀(PG, 0019·상호 TLS·저장 암호화·동기 복제) 통과 · `make coverage` 전체 80/80 · 엄격 43/43. 부하(prod·PG, 같은 VM 에서 클라이언트·DB 동거): 작업 2 = 374 rps·p95 342ms(동시 64)·경부하 p50 8ms / 작업 16 = 1,776 rps, 관문 실행 p95 예산 이내 — 23차 결과.

품질 지표의 한계와 실측(43차, `make corpus-eval`): 자체 공격셋·합성 표본(골든셋 오탐 0.00%, 합성 인젝션 34건 미탐 5.9%)은 낙관적이었다. **공개 코퍼스 고정 판 실측** — 주입·탈옥 미탐률은 배포 엔진(규칙 + 분류기) 기준 **41.1%**(JailbreakBench 공격 산출물 1,097건 50.4% · garak 700건 26.6%, 규칙만이면 72.9% · 63.7%)로 NFR-Q2 목표(1단계 ≤ 20%, 정상 운영 ≤ 10%)에 **미달**이다. 놓치는 것은 설득형(PAIR 86%)·적대 접미사(GCG 88%)·DSN(89%)처럼 지시 덮어쓰기 표식이 없는 유해 요청 포장이고, 템플릿형(JBC·무작위 탐색 0%)·DAN(8%)은 잡는다. 정상 오탐은 XSTest 안전 질문 0.4% · GSM8K 0.1%. 기법 없는 유해 요청(HarmBench 90%·XSTest 위험 99.5% 미탐)은 D1 탐지 대상 밖이라 참고값. 측정으로 찾은 결함 2건(d6-07 조회 도구 오탐 26%, D1 직접 지시 덮어쓰기 미탐)은 24차에서 고쳤다. 브라우저 E2E 는 헤드리스 Chromium. **50차 — D1-03 깊은 검사**(검증된 안전 분류 모델 Qwen3Guard-Gen-0.6B, Apache-2.0, 자체 호스팅·학습 데이터 작성 없음): 응답 뒤 비동기로 보면 주입·탈옥 미탐 **9.7%**(JailbreakBench 8.0%·garak 12.4%, PAIR 11%·GCG 18%·DSN 13%), 유해 요청 HarmBench 9.2%·XSTest 위험 21.0%. 대가는 정상 경보 — 골든셋 1,000건 0%·GSM8K 0.1%·XSTest 안전 5.2%(하한 0.8 이면 2.8%·미탐 15.5%). 모델은 CPU 에서 입력 1건 p50 1.1 s·p95 4.0 s라 인라인 예산에 못 들어가 **경보만**(차단 불가)이고, 처리량을 넘는 요청은 건너뛰고 센다.

## 트러블슈팅 (실제 겪은 것)

| 증상 | 원인 | 해결 |
|---|---|---|
| `make prod-all` → `port is already allocated` | local 이 8000 을 점유 | `make local-stop` 후 prod, 또는 `API_PORT=18000 WEB_PORT=13000` |
| 이미지 빌드가 MDS3 받기에서 `HTTP Error 429: Too Many Requests` (54차) | FIDO MDS 가 IP 별 요청 빈도를 제한 — 같은 IP 에서 짧게 여러 번 받으면 수십 분 이상 막힘 | 빌드 캐시(7일)·캐시 사본 대체로 요청을 줄인다. 급하면 `FIDO_MDS_OPTIONAL=1` 로 스냅숏 없이 빌드(허용목록 테넌트 등록은 닫힌 실패) 후 풀리면 다시 빌드 |
| 같은 동네 망 전환에도 재인증 (55차) | DB-IP Lite 의 도시 이름이 동 단위("Yongsan-dong (Hangang-daero)") | 표시 = 나라 · 시도, 새 위치 = 나라 변경 또는 `GEO_SAME_PLACE_KM`(100 km) 밖 |
| OpenBao 리더를 멈춘 순간 임대 1건 `HTTP 307` 실패 (56차) | 선출 중 대기 노드가 POST 를 리다이렉트(urllib 은 따라가지 않음), 두 대기 노드가 모두 307 | 307·503·연결 실패 = 미처리 → 다음 노드, 전 노드 미처리면 1 s 쉬고 최대 3바퀴(시간 초과는 재전송 안 함) |
| `bao_setup.py cluster-init` 가 `HTTP Error 429` | 대기 노드의 `sys/health` 는 429 | `sys/health?standbyok=true` |
| OpenBao 노드가 재기동 뒤 계속 재시작 "Error parsing Seal configuration … no such host" | 자동 봉인 해제기(transit)가 없으면 노드는 봉인 상태로도 뜨지 않는다 | 봉인 해제기 기동·`make bao-cluster-unseal` → 노드는 스스로 풀림 |
| `docker compose start bao-*` 가 "missing dependency tls-init" | tls-init 은 `run --rm` 으로만 돌아 컨테이너가 없다 | `up -d --no-deps <노드>` |
| 접근성 점검 `/domains/d8/context` target-size(serious) (9차 게이트) | 최근 추적 칩 링크(높이 20px)가 데이터가 늘며 여러 줄로 붙음 | 링크를 `inline-flex min-h-6`(24px) |
| 접근성 점검 전 경로 reflow 320px 2px 초과 (9차 게이트) | 헤더 테넌트 선택 상자 폭 = 가장 긴 테넌트 이름(시험이 만든 긴 이름) | 선택 상자 `max-w-48` |
| 객체 저장에 버킷 만들기 403 AccessDenied | S3 자격 증명에 버킷 생성(Admin) 권한 없음 | 권한을 백업 버킷 하나로 한정해 부여(`Admin:aegis-backup` 등) |
| SeaweedFS 가 8181·9101·18333 을 0.0.0.0 평문으로 엶 | Iceberg·Lance 카탈로그 기본 켜짐, S3 gRPC 기본 평문 | `-s3.port.iceberg=0 -s3.port.lance=0`, `security.toml` 로 gRPC 상호 TLS, 나머지는 `-ip.bind=127.0.0.1` |
| `security.toml` 을 넣자 S3 IAM "no signing key found for STS service" | filer 서명 키 필요 | 기동마다 무작위 `jwt.filer_signing` 키를 덧붙임(infra/objstore/start.sh) |
| `make certs-rotate`·tls-init 가 새 인증서 설정을 반영 안 함 | tls-init 은 api 이미지에 구워진 scripts/certs.py 를 쓴다 | 이미지를 다시 빌드한 뒤 회전 |
| `make corpus-eval` 이 수십 분 뒤 137 로 끝나고 결과가 없음 | 같은 호스트의 다른 프로젝트가 로컬 스택 컨테이너를 지움(OOM 아님) — 끝난 행도 커밋 전이라 사라짐 | 코퍼스·변형 행마다 커밋(50차), `make local-all` 후 재실행 |
| `make guard-up` 뒤 `make test` 의 코퍼스 시험이 깊은 검사까지 돎 | 시험 컨테이너가 `infra/guard/api.env` 의 GUARD_URL 을 물려받음 | conftest 에서 GUARD_URL 을 비움(test_guard 는 가짜 서버) |
| local worker 가 조용히 멈춤(`Exited (1)`), 주기 작업(고정 판·격리 점검 등)이 안 돎 | 주기 루프 밖(점검 대상 조회)에서 SQLite `database is locked` 예외 — local 은 재시작 정책 없음(10차 게이트) | 주기 실패를 기록하고 다음 주기로(worker 루프). local SQLite 는 쓰기 하나뿐 — 접근성 전 경로 점검처럼 화면 요청이 몰리면 DPoP jti 쓰기가 줄을 선다 |
| `make e2e-a11y ONLY=…/[id]/…` 만 돌리면 그 화면이 401·빈 화면 | 목록 화면 없이 동적 템플릿만 주면 `[id]` 를 글자 그대로 열고, 이중 인코딩된 경로가 DPoP htu 와 달라 401 | ONLY 에 목록 화면(예: `/incidents`)을 함께 넣는다 — 실제 ID 쪽 결과로 판정 |
| 접근성 점검 중간부터 화면이 오류(DPoP 증명 거부) | web dev 서버가 메모리 초과로 재시작(OOM) — 점검 브라우저의 DPoP 묶인 세션이 새 서버와 맞지 않음 | web 재기동 뒤 점검을 다시(새 로그인). 같은 VM 의 다른 스택 메모리를 `docker stats` 로 확인 |
| prod OTLP 내보내기 실패(`otel-collector` 이름 풀이 실패) | VM 재시작 뒤 otel-collector 만 꺼진 채(재시작 정책 없음) | `$(DC) up -d otel-collector` — 판정 경로는 막히지 않는다(관측 실패 무시) |
| 부하 중 처리량이 급락하고 p99 가 수 초 | 같은 주체의 반복 공격이 열린 사건 한 행을 요청마다 갱신·잠금(66차 실측 최대 ~140 연결 대기) | 사건 덧붙이기를 증적 작성기로(묶음마다 사건당 1회, 66차). 확인: `pg_stat_activity` 의 `Lock` 대기 질의 |
| 같은 부하 시험을 바로 반복하면 처리량이 절반 이하 | 앞 실행의 증적 비동기 적재 잔량(~30 s)·외부 복사(WAL)가 CPU 를 쓴다 | 실행 사이 60 s 이상 두고, 같은 VM 의 다른 스택 부하를 `docker stats` 로 함께 기록 |
| `make l2-up` 이 unhealthy, health `sidecar "gvisor_sentry" not usable` | 새 gVisor 판은 runsc 옆 `gvisor-bin/` 사이드카가 필요(STRICT) | 이미지에 `gvisor-bin` 함께 복사(65차) — 판을 올릴 때 묶음 구성 확인 |
| L2 판정이 `L2 샌드박스 종료 (code 128)` 로 강등 | 읽기 전용 샌드박스 루트 FS 에 번들 붙일 자리(/agent)가 없음 → runsc 기동 실패 | 이미지에 `/sandbox-rootfs/agent` 를 만든다(65차). 원인 확인: `runsc --debug --debug-log=/tmp/dbg/ do …` |
| `make injguard-up` 뒤 한국어 정상 입력이 D1-03 차단(model-block) | 주입 모델이 영어 학습 — 한국어 정상 문장도 0.998+ (64차 부하 시험에서 발견) | 엔진이 라틴 문자 비율 0.8 미만 입력은 모델을 묻지 않음(규칙·분류기만). 같은 증상이면 엔진 판(D1-03 1.3.0)·`explain` 의 `latin` 확인 |
| 안전 분류 모델 1건 3 s 가까이 걸림 | 모델 카드 방식(생성 24 토큰)·긴 고정 지시문을 매번 처리 | "Safety:" 뒤 첫 토큰 확률 1회 순전파 + 고정 앞부분 KV 캐시(등급 일치 확인) |
| 대기 서버 기동 실패 "max_connections = 100 is a lower setting than on the primary" | 핫 스탠바이는 주 서버 이상의 max_connections 필요 | 대기·복구 서버에 `DB_MAX_CONNECTIONS` 전달(compose) |
| `make test` 가 137 로 끝남 | 같은 프로젝트에서 `make local-stop`(--remove-orphans)이 실행 중인 시험 컨테이너를 지움 | 시험과 스택 정지를 동시에 돌리지 않는다 |
| 일시 정지했던 db 를 되살린 직후 `up --wait` 이 "is unhealthy" | 정지 중 실패한 헬스 검사가 남아 있고 `--wait` 는 unhealthy 를 기다리지 않음 | 헬스 상태 폴링 후 진행(scripts/dr_drill.sh) |
| 대기 서버를 승격한 뒤 주 서버의 원장 커밋이 멈춤 | 승격된 서버는 더 이상 동기 대상이 아니라 `synchronous_standby_names` 대기 | `make db-sync ENV=prod MODE=off` 먼저 → 대기 서버 재복제 → 자동 재등록 |
| 앱이 자기 DB 연결의 TLS 를 `pg_stat_ssl` 로 못 봄 | `SET ROLE aegis_app` 뒤에는 세션 사용자 행이 숨겨짐 | libpq(클라이언트) 쪽 `ssl_in_use`·sslmode 로 확인 |
| 인증서 회전 중 부하 클라이언트가 빈 응답 | SIGHUP 으로 은퇴하는 작업 프로세스가 keep-alive 연결을 닫음 | 응답 전에 닫힌 재사용 연결만 새 연결로 1회 재전송(표준 HTTP 클라이언트 동작) |
| prod API 를 curl 로 부르면 연결이 끊김 | prod api 는 클라이언트 인증서 필수(상호 TLS) | `make certs-client ENV=prod NAME=operator` → `--cacert/--cert/--key` |
| `bao-up MODE=server` 가 "network … not found" | 지워진 옛 네트워크를 가리키는 bao-server 컨테이너 | 컨테이너만 재생성(`… --profile bao-server rm -sf bao-server`, raft 볼륨 유지) |
| `KMS_BACKEND=openbao` 로 쓴 기록이 OpenBao 재기동 뒤 안 열림 | dev 서버는 메모리 저장이라 transit 키가 사라짐 | KMS 는 영속 OpenBao(raft)만. 시험은 일회용 DB 로 |
| `make kms-rewrap` 뒤 findings 표가 커짐 | 갱신된 행만큼 PostgreSQL 죽은 튜플 | autovacuum 또는 `VACUUM (ANALYZE) findings` |
| prod api `/health` 503, `failed to resolve host 'db'` | 포트 충돌로 네트워크 설정 실패한 컨테이너가 재사용됨 | `make prod-stop && make prod-all` 로 재생성 |
| `No module named 'mcp.server.fastmcp'` | MCP Python SDK 2.x 에서 FastMCP → `MCPServer` | `mcp>=2.3,<3` 고정, `mcp.server.mcpserver` 사용 |
| 동시 요청 시 원장 체인 분기 (SQLite) | SQLite 는 `SELECT … FOR UPDATE` 무시 | 머리 행 무변경 UPDATE 로 쓰기 잠금 선점 (`app/ledger.py`) |
| 원장에 직접 넣은 행을 지울 수 없음 | 추가 전용 트리거(의도된 동작) | 운영 DB 에 직접 INSERT 금지. 리허설 볼륨만 초기화 가능 |
| 다른 프로젝트가 8000/3000 점유 | 같은 호스트의 다른 compose 프로젝트 | `API_PORT=18000 WEB_PORT=13000 make prod-all` (셸 env 가 env 파일보다 우선) — 다른 프로젝트를 멈추지 않는다 |
| 콘솔 버튼 클릭 시 422 `decision 은 approve\|reject` | JS 실행 환경 서버 액션 FormData 에 버튼 name/value 미포함 | 결정별 서버 액션을 버튼 `formAction` 으로 분리 (`app/approvals/actions.ts`) |
| 메모리 폭주 번들이 등록됨 | 재생 예외를 강등 판정으로 흡수 | R4 에서 재생 중 예외·무효 판정 1건이라도 있으면 보류 |
| 거버넌스 점검 `D10-02.retention-short` | regulated-kr(1825일) 적용 중 기본 보존 90일 | regulated-kr 운영 시 `EVIDENCE_RETENTION_DAYS=1825` |
| PostgreSQL RLS 가 효과 없음 | 테이블 소유자·슈퍼유저는 RLS 를 우회 | 0006 이 비특권 역할 `aegis_app` 을 만들고 앱 연결이 `SET ROLE` (마이그레이션은 소유자로) |
| 0006 이 SQLite 에서 `DateTime type only accepts Python datetime` | 표 재생성 시 원문 SELECT 결과를 파이썬으로 옮김 | SQL `INSERT … SELECT` 복사. 실패한 마이그레이션이 남긴 빈 표는 행 0 확인 후 삭제 |
| 로그아웃 후 `http://0.0.0.0:3000/login` | 라우트 핸들러 `req.url` 이 컨테이너 바인드 주소 | Host/X-Forwarded-* 기준 리다이렉트 |
| 편집기 시험이 입력한 YAML 대신 초기값으로 | React 19 는 폼 액션 후 비제어 입력을 초기화 | 제어 상태 textarea · 직접 제출(startTransition) |
| 수집기 경고 `paths were modified to include their context prefix` | OTTL 0.162 문맥 접두사 경로 권장 | 생성기에서 `span.`·`log.`·`datapoint.` 접두사 |
| L1 하위 프로세스가 첫 요청 전에 종료 | 감사 훅이 `sys._getframe` 을 막아 pydantic 실패 | 거부 목록에서 제외 (커널 층이 경계) |
| 서드파티 등록 직후 내장 에이전트로 되돌아감 | local `--reload` 가 `/app/data` 까지 감시 → 재기동·자동 시드 / 내장 동기화가 api 행을 덮어씀 | 핫리로드 감시를 소스 디렉터리로 한정, 내장 동기화는 api 출처 행을 건너뜀 |
| prod 리허설이 구 마이그레이션 | `make prod-all` 은 재빌드하지 않음 | 코드 변경 후에는 `make prod-build` |
| k3d 이미지 반입 `content digest … not found` | Docker Desktop 다중 아키텍처 인덱스 | 노드 아키텍처만 `docker save --platform` → `ctr import` (`scripts/k8s_rehearsal.sh`) |
| CLI 가 `GLIBC_2.38 not found` | 빌드 이미지가 glibc 2.41 | bookworm(glibc 2.36)에서 빌드 |
| 처리량 100 rps 대·p95 1초 | 판정마다 원장 9건 동기 적재 + 체인 머리 잠금을 커밋까지 보유 | 증적 비동기 묶음 적재(`EVIDENCE_ASYNC`) |
| 같은 주체 반복 차단 시 p99 수 초 | 사건 행 ID 목록이 끝없이 커짐 | 최근 200건 + 총계 열(0011) |
| 작업 8 이상에서 500 `too many clients` | 프로세스당 풀 × 작업 수 > PostgreSQL 100 | `DB_POOL_SIZE`·`DB_MAX_OVERFLOW`·`DB_MAX_CONNECTIONS` |
| 원장 검증 중 작업 프로세스 종료(100만 건+) | 체인 전체를 메모리에 적재 | 서버 커서로 흘려 읽는 검증(26차) |
| 부하 직후 원장 검증 ok=false | 적재 중 기록·머리를 다른 시점에 읽음 | 머리 seq 까지만 검증 |
| SSO 두 번째 사용자가 OTP 에서 실패 | 콘솔 로그아웃 후에도 IdP 세션 유지 | 사용자 전환 시 IdP 로그아웃 (IdP 로그아웃 연동은 후속) |
| A2A 요청이 모두 422 `query.request` | `from __future__ import annotations` + 함수 안 import 로 FastAPI 가 Request 주석을 못 풂 | 모듈 상단 import |
| 콘솔 로그인 직후 다음 화면에서 로그아웃 | `WEB_SESSION_SECRET` 없이 번들(서버 액션·라우트·화면)마다 임의 봉인 키 → DPoP 키 쿠키를 못 엶 | 프로세스 공용 + `.next/cache/aegis-web-secret` 보관, 여러 인스턴스면 env 필수 |
| 콘솔 사용 중 갑자기 "세션 만료"로 로그인 화면 (local) | Next dev 서버가 메모리 임계로 자동 재시작하며 `.next/` 를 비워 봉인 키가 새로 생김 → 기존 세션 쿠키를 못 엶 (39차 접근성 전 경로 점검 중 발견) | 대체 봉인 키를 `.next/cache/aegis-web-secret` 에 둔다(재시작에도 유지). 여러 인스턴스·prod 는 `WEB_SESSION_SECRET` 필수 |
| 코퍼스 반입이 "68행 JSON 오류"로 실패 | `str.splitlines()` 가 JSON 문자열 안의 U+2028·U+0085 에서도 줄을 자름 (43차) | JSONL 은 `\n` 으로만 나눈다(`quality._items`) |
| `make bao-up MODE=server` 가 init 에서 시간 초과 → 다시 하면 '이미 초기화' | raft 부트스트랩이 5초를 넘겨 응답(봉인 해제 키)을 놓침 (46차) | 초기화만 120초 대기. 키를 잃었으면 리허설 볼륨(baodata·baoaudit)을 지우고 다시 |
| OpenBao 감사 장치 활성화 400 "use declarative, config-based audit device management" | OpenBao 2.4 는 API 로 감사 장치를 켜지 못한다 (46차) | `infra/openbao/config.hcl` 의 `audit` 블록으로 선언 |
| `make bao-up` 상태에서 `make test` 의 신원 시험 실패 | 시험 컨테이너가 `infra/openbao/api.env` 를 물려받아 내장 브로커 시험이 실제 OpenBao 를 침 (46차) | `test/conftest.py` 가 SECRETS_BACKEND=builtin 으로 고정 |
| prod 에서 에이전트를 새 판으로 롤링 교체했는데 상세 화면이 옛 판·옛 기본 엔진 | `reload_agent` 가 `version` 만 바꾸고 저장된 매니페스트는 그대로 (7차 prod 회귀에서 발견) | 교체 시 매니페스트·이름·예산·실패 모드도 갱신. local 은 기동 시드가 맞춰 줘서 드러나지 않았다 |
| prod 에서 탈취 토큰 재사용이 500, 폐기도 롤백 | 인증 단계(범위 설정 전) 기록이 PG RLS 에 막힘 | 탈취·이상 세션 대응은 시스템 범위(`*`)로 기록 |
| `/profiles/{id}:compare` 404 | GET `/profiles/{id}` 가 먼저 잡음 | `/profiles/{id}/compare` |
| 만료 승인 결정 409 뒤 상태가 pending | 자동 거절이 오류와 함께 롤백 | 거절을 커밋한 뒤 409 |
| Playwright Python 이미지에서 `No module named 'playwright'` | 공식 이미지는 브라우저만 | `infra/e2e` 이미지(빌드 때 `pip install playwright==1.55.0`) |
| curl 로 받은 토큰을 Python 으로 쓰면 재인증 요구 | 묶이지 않은 API 세션까지 UA(기기) 비교 | 기기 비교는 DPoP 로 묶인 콘솔 세션만 |

## 결정·가정 (2026-10-08, 1~9차 실행)

- 1차: 로드맵 0~1단계 + 원장·승인·콘솔 핵심. 정책 = 내장 YAML 평가기(OPA 교체 가능), 원장 = RDB 해시 체인(ClickHouse 교체 가능). 내장 규칙 에이전트는 격리 L0.
- 2차: Epic 7~12, C3 = worker 주기 점검, R4 = 하위 프로세스 재생, 콘솔 E2E = 헤드리스 Chromium(Claude in Chrome 미연결).
- 3차: Epic 13~19 — 테넌시 = 앱 계층 강제 + PG RLS 이중(원장 체인 테넌트별), 인증 = 로컬 계정 + 서명 세션·API 토큰 + OIDC 설정 슬롯(화면설계는 정적 비밀번호 금지 — 로컬 계정은 초기·비상·폐쇄망용으로 둔다), 샌드박스 = L1 실구현·L2/L3 보류. SPIRE·OpenBao·Harbor 대신 내장 발급자·임대 브로커·번들 반입으로 같은 계약 제공.
- 4차: Epic 20~26 — k8s = 로컬 k3d 실제 설치 리허설, SSO 시험 IdP = 로컬 Keycloak 26.3(`idp` 프로파일), 성능 = 측정 + 병목 개선 후 실측 보고(NFR-P1 2,000 rps 는 이 VM 에서 1,776 rps 확인), A2A = v1.0 규격(PascalCase 메서드), 영어 = 서버 렌더 gettext 방식(에이전트 작성 문구·런북은 원문).
- 5차: Epic 27~34 — 범위 = 도메인 상세 27화면 + 에이전트 설정·작업 흐름·로그인 보안·공정성/카드(P2). 에이전트 설정 = 정책 버전 `agentParams`(정책 값이 호출자 값보다 우선), 패스키 시험 = 로컬 Playwright + CDP 가상 인증기. WebAuthn·DPoP 검증은 외부 라이브러리 없이 `cryptography` 로(증명 'none', 기기 신뢰 안 함), 위치 = IP 대역만, 2단계는 등록한 사용자에게 강제(미등록은 경고).
- 6차: Epic 35~41 — 원본 PDF 에서 다시 만든 One-Page PRD.md 기준. OQ1 = 미리보기 표본 **테넌트 옵트인 + 2인 승인**(마스킹·N건·D일), OQ3 = **특권 역할 2단계 강제**(테넌트 상향 가능, SSO·서비스 계정 제외), OQ2 = L3 없으면 **R4 L1 대체 + 경보 전용**(차단 전환 2인, 실행 시 L2/L3 요구 에이전트는 보류 유지). 접근성 = axe-core 자동 점검(수동 점검은 범위 밖), 영어 = 런북·규칙은 번들 안 영어 파일, 엔진 근거 메모는 콘솔 카탈로그 패턴. OpenBao = 토큰 역할 기반 임대(dev 서버 리허설), 기본값은 내장 브로커.
- 7차: Epic 42~46 — OQ4 = **자체 경량 분류기**(문자·단어 n-gram 로지스틱, 순수 파이썬, 합성 학습셋 + 저장소 시험셋, 가중치 해시를 엔진에 고정), 공개 코퍼스는 **이미지 빌드에서 GitHub 고정 커밋**으로 받아 **평가 전용**(학습 금지). 화면설계서 '최소 폭 1280px' 와 WCAG 1.4.10 상충은 1024px 이상은 설계서 그대로, 좁은 화면만 재배치로 해소. OpenBao 운영형은 단일 노드 raft·수동 봉인 해제·설정 선언 감사 장치로 리허설. 제외: L2/L3 microVM(이 환경에 런타임 없음), OQ5~OQ7(결정 전).
- 8차: Epic 47~50 — 원장 RPO 0 = **PG 동기 복제**(원장 트랜잭션만 `synchronous_commit=on`, 나머지 local), NFR-D2 키 = **OpenBao transit + builtin 대체**(값 단위 봉투 암호화, 원장은 추가 전용이라 새 기록부터), NFR-D3 = prod 내부 4구간 상호 TLS(local 은 평문 개발 모드), OQ9 = D1-03 확장 — 엔진 출처는 BLOCKED 질문 답대로 **검증된 안전 분류 모델**(Qwen3Guard-Gen-0.6B, 학습 데이터 작성 없음), CPU 지연이라 응답 뒤 깊은 검사(경보만), 하한 `GUARD_UNSAFE_MIN=0.5`.
- 10차: Epic 57~68 — 원장 평문 = **통제된 재암호화**(2인 승인·서명 증명서·만료 창 안에서만 DB 트리거가 '평문 → 암호문, 다른 열 불변' 허용, 해시 체인 그대로). OQ5(증적 열 지향 DB)·OQ6(외부 정책 엔진) = 현행 유지 + 전환 조건 기록. 인라인 모델 = 영어 학습 고정 판이라 라틴 문자 입력만, 배치는 `ENGINE_OVERRIDES`. L2 = gVisor 를 compose 브로커로(Docker 데몬 설정 없이), seccomp·AppArmor 만 unconfined. agentgateway = ExtMCP(gRPC) 정책 서버로 연결(local). HSM = SoftHSM2 로 PKCS#11 경로 리허설(실제 HSM 은 lib·토큰만 교체). 2,000 rps 는 공유 VM 측정 한계 — BLOCKED 질문 답대로 최고 1,797 rps 를 리허설 값으로 수용, 확인은 전용 노드.
- 9차: Epic 51~56 — 깊은 검사 경보 후속 = **세션 격리**(같은 주체·세션의 다음 요청 인라인 차단, 해제 2인·기한 1시간), 지오 IP(DB-IP Lite, CC BY 4.0)·FIDO MDS3 = **이미지 빌드 고정 판**. MDS3 BLOB 은 같은 주소가 매달 바뀌어 해시 고정 대신 FIDO 서명 체인(GlobalSign Root CA - R3 지문 고정·서명자 이름·CRL) 검증 = 고정 근거, 검증 실패 = 빌드 실패. 증명 형식은 packed(x5c)만, 허용목록 없는 테넌트는 소유 증명만(MDS 가 유출·우회를 보고한 기종만 거부). 불가능한 이동 = 경보·재인증(차단 아님). OpenBao = 같은 호스트 봉인 해제기(transit) + 3노드 raft(prod 리허설), 저장 암호화 KEK 는 클러스터로 옮기지 않음. CLI 영어 = 사람이 읽는 줄·도움말만(JSON 은 그대로).
- 계획표·가정 전체: `.wds/plan.md`.
