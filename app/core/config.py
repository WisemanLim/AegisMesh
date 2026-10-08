"""aegismesh — settings (env 주입: .env.local | .env.prod 는 compose env_file 로 전달)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_name: str = "aegismesh"
    app_env: str = "local"
    db_engine: str = "sqlite"
    database_url: str = "sqlite:////app/data/app.db"
    auto_migrate: bool = False                       # true 면 기동 시 alembic upgrade + seed (local 전용 권장)
    ledger_signing_key: str | None = None            # base64 Ed25519 개인키 32바이트. 없으면 ledger_key_file 생성
    ledger_key_file: str = "/app/data/ledger_ed25519.key"
    ledger_checkpoint_every: int = 100               # N 건마다 서명 체크포인트
    evidence_async: bool = True                      # 인라인 판정 증적은 큐 → 묶음 적재(NFR-L5). false = 요청 안에서 동기 적재
    evidence_queue_max: int = 20000                  # 적재 대기열 한도 — 80% 이상이면 표본 적재로 강등(50% 이하 복귀)
    evidence_sample_every: int = 10                  # 강등 중 allow 판정은 N 건 중 1 건만 적재(나머지는 계수·원장 기록)
    evidence_batch_max: int = 500                    # 묶음 1 트랜잭션 최대 건수
    fp_budget_min: int = 2                           # 하루 오탐 예산 최소 건수 (예산 = max(최소, 인라인 판정 × 0.5%), NFR-Q6)
    webauthn_rp_id: str = "localhost"                 # 패스키 RP ID = 콘솔 도메인(SCR-B02) — 다른 도메인 자격증명 거부
    webauthn_rp_name: str = "AegisMesh"
    webauthn_origins: str = "http://localhost:3000"   # 허용 origin(쉼표) — 콘솔 주소
    fairness_interval_sec: int = 604800              # worker 공정성 정례 측정 주기(SCR-N06 주 1회)
    approval_ttl_min: int = 240                      # 사람 승인 요청 만료(분) — 만료 시 자동 거절 (SCR-O06)
    fp_recover_days: int = 7                         # 오탐 예산 강등 후 복귀 조건 기간(7일 오탐률 ≤ 0.5%)
    quality_check_interval_sec: int = 300            # worker 오탐 예산 점검 주기
    golden_interval_sec: int = 604800                # worker 골든셋 1만 건 재생 주기(주간, NFR-Q1)
    hot_cache_ttl_sec: float = 2.0                   # 인라인 판정 바인딩 조회 캐시(이 프로세스 쓰기는 즉시 무효화, 0 = 끔)
    db_pool_size: int = 10                           # 프로세스당 DB 연결 풀 (작업 프로세스 수 × (풀+초과) ≤ DB max_connections)
    db_max_overflow: int = 10
    worker_interval_sec: int = 30                    # 상시 점검 worker 주기
    registry_dir: str = "/app/data/registry"         # 심사 통과한 서드파티 에이전트 번들 저장
    review_cpu_sec: int = 20                         # 등록 심사 R4 재생 하위 프로세스 CPU 한도
    evidence_retention_days: int = 90                # 증적 온라인 보존(PRD §12.6 기본 90일, regulated-kr 1825일)
    model_egress: str = "deny"                       # 외부 모델 호출 정책(NFR-D5 기본 국내 처리)
    otel_endpoint: str | None = None                 # 관측 수집기(OTLP) — 미설정이면 D10-07 경보
    otel_allow_trace_ratio: float = 1.0              # allow 판정 추적(span) 표본 비율 — 비허용·강등·예산 초과는 항상, 지표는 전부(NFR-P1, Epic 66)
    governance_interval_sec: int = 3600              # worker 거버넌스 자체 점검 주기
    redteam_interval_sec: int = 86400                # worker 레드팀 캠페인 주기
    auth_secret: str | None = None                   # 세션·API 토큰 서명 비밀. 없으면 auth_secret_file 생성(로컬·리허설용)
    auth_secret_file: str = "/app/data/auth_secret.key"
    oidc_issuer: str | None = None                   # 조직 SSO(OIDC) 초기값 — 콘솔(/admin/sso)에서 저장하면 DB 설정이 우선
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None            # 기밀 클라이언트일 때만. 기본은 공개 클라이언트 + PKCE(S256)
    oidc_backchannel_map: str | None = None          # 서버 간 호출 주소 치환 "http://localhost:8080=http://keycloak:8080"
    tenancy_test_interval_sec: int = 86400           # worker 테넌트 교차 접근 시험 주기(SCR-R01 매일)
    spiffe_trust_domain: str = "aegismesh.local"     # 워크로드 신원 신뢰 도메인 (spiffe://<td>/…)
    svid_ttl_sec: int = 3600                          # JWT-SVID 수명 — 50% 시점에 worker 가 회전
    svid_signing_key: str | None = None              # base64 Ed25519 개인키. 없으면 svid_key_file 생성(로컬·리허설용)
    svid_key_file: str = "/app/data/svid_ed25519.key"
    secret_lease_max_sec: int = 900                  # 동적 시크릿 최대 수명(갱신 포함) — 기본 15분
    secrets_backend: str = "builtin"                 # 동적 시크릿 임대 엔진 builtin | openbao (Epic 41)
    openbao_addr: str = "http://bao:8200"            # OpenBao API — 토큰 역할 aegis-lease 로 임대 발급
    openbao_token: str | None = None                 # 브로커 토큰(정책 aegis-broker: 역할로 만들기 + accessor 조회·갱신·회수) — 루트 토큰 금지
    openbao_ca_file: str = ""                        # 상호 TLS(Epic 56 운영형 클러스터) — 내부 CA · 클라이언트 인증서·키. 비우면 TLS 검증 기본값
    openbao_client_cert: str = ""
    openbao_client_key: str = ""
    corpora_dir: str = "/corpora"                    # 공개 공격 코퍼스 반입본(infra/corpus 이미지 → 볼륨) — 없으면 정기 실측 건너뜀
    corpus_interval_sec: int = 604800                # 공개 코퍼스 정기 실측 주기(주 1회, NFR-Q2)
    tls_dir: str = ""                                # 내부 상호 TLS 인증서(ca.crt·tls.crt·tls.key, prod=/tls — Epic 48 NFR-D3). 비우면 평문(local)
    kms_backend: str = "builtin"                     # 저장 암호화 KEK 위임처 builtin(키 고리 파일) | openbao(transit) — Epic 49 NFR-D2
    kms_transit_key: str = "aegis-kek"               # OpenBao transit 키 이름 (scripts/bao_setup.py 가 만든다)
    kms_keyring_file: str = "/app/data/kms_keyring.json"   # builtin KEK 키 고리(버전별, 비커밋·0600)
    kms_dek_ttl_sec: int = 3600                      # 프로세스 DEK 교체 주기 — KEK 회전 뒤 새 쓰기가 새 버전으로 넘어가는 상한
    guard_url: str = ""                              # 안전 분류 모델 서버(compose guard, Epic 50) — 비우면 D1-03 깊은 검사 끔
    guard_queue_max: int = 200                       # 깊은 검사 대기 상한 — 넘치면 건너뛰고 센다(모델 처리량 보호)
    guard_workers: int = 2                           # 깊은 검사 동시 요청 수(모델 서버는 한 번에 하나씩 추론)
    guard_quarantine_sec: int = 3600                 # 깊은 검사 경보 → 같은 주체·세션 격리 기한(0 = 격리 안 함, 경보만) — Epic 51
    s3_endpoint: str = ""                            # 백업 외부 복사 객체 저장(S3, Epic 52) — prod https://objstore:8333(상호 TLS). 비우면 끔
    s3_bucket: str = "aegis-backup"
    s3_region: str = "us-east-1"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    offsite_interval_sec: int = 60                   # 외부 복사 주기 — 일반 데이터 RPO(호스트 상실) 상한 ≈ archive_timeout + 이 값
    db_backup_keep: int = 12                         # 기본 백업 보관 개수(원격 정리에도 같은 값, infra/postgres/backup.sh 와 같은 env)
    identity_backend: str = "builtin"                # 워크로드 신원 발급처 builtin(내장 Ed25519) | spire(Epic 53, Workload API·ES256)
    spire_agent_socket: str = "/run/spire/agent/api.sock"    # api 와 PID 네임스페이스를 함께 쓰는 spire-agent 의 Workload API
    spire_server_socket: str = "/run/spire/server/api.sock"  # 등록 항목 동기화(관리 소켓)
    spire_node_id: str = ""                          # 등록 항목 부모(노드 별칭). 비우면 spiffe://<td>/node/api
    geoip_db: str = "/opt/geoip/dbip-city-lite.mmdb"   # 지오 IP(DB-IP Lite, CC BY 4.0) — 이미지 빌드 고정 판(sha256), Epic 55
    geo_same_place_km: int = 100                     # 이 거리 안(같은 나라)이면 같은 위치 — 대도시권 망 전환은 재인증 안 함
    geo_travel_max_kmh: int = 900                    # 불가능한 이동 속도 하한(여객기 순항 ≈ 900 km/h)
    geo_travel_min_km: int = 500                     # 이보다 가까운 이동은 속도를 보지 않는다(도시 수준 DB 오차·인접 도시)
    engine_overrides: str = ""                       # 에이전트 기본 엔진 바꾸기 "d1-03=injection_model" — make injguard-up 이 넣는다(Epic 64)
    bus_url: str = ""                                # 발견 버스 NATS(Epic 60) — local nats://nats:4222 · prod tls://nats:4222(상호 TLS). 비우면 끔
    bus_stream: str = "AEGIS"                        # JetStream 스트림(주제 aegis.>)
    bus_max_age_days: int = 7                        # 스트림 보존 — 소비자 재생 가능 기간
    bus_poll_sec: float = 1.0                        # 중계 주기(원장 커서 확인)
    bus_start: str = "head"                          # 첫 기동 커서 head(지금부터) | all(원장 처음부터)
    bus_ca_file: str = ""                            # 상호 TLS — 내부 CA·클라이언트 인증서(prod /tls)
    bus_client_cert: str = ""
    bus_client_key: str = ""
    ledger_rewrap_window_sec: int = 21600            # 원장 재암호화 창 수명(2인 승인 뒤, Epic 57) — 지나면 트리거가 다시 모든 갱신을 막는다
    ledger_rewrap_batch: int = 2000                  # 재암호화 묶음 크기(묶음마다 커밋 — 원장 적재와 잠금 경합을 짧게)
    fido_mds_dir: str = "/opt/fido"                  # FIDO MDS3 스냅숏(이미지 빌드 때 받고 검증, Epic 54) — AAGUID 허용목록 테넌트의 증명 체인 근거
    sandbox_l1_slots: int = 4                        # L1 동시 실행 슬롯(요청 단위 임대)
    sandbox_queue_sec: float = 2.0                   # 풀 고갈 시 대기 후 거부 (격리 강등 금지)
    sandbox_recycle_uses: int = 200                  # 웜 하위 프로세스 회수 주기(사용 횟수)
    sandbox_call_timeout_sec: float = 2.0            # 경로 밖(offline) 판정 1건 시간 한도
    sandbox_cpu_sec: int = 60                        # 웜 하위 프로세스 누적 CPU 한도
    sandbox_l2_url: str = ""                         # L2 격리 브로커(gVisor, compose sandbox-l2) — make l2-up 이 넣는다. 비면 L2 없음(Epic 65)


settings = Settings()
