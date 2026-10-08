# COMPLIANCE — 정보통신·SaaS (ICT / SaaS — 기본 베이스라인) (KSIC J)

> 자동 생성 (wds-scaffold, 2026-10-06). 근거: `domains/ict-saas.yaml` + `.docs/AegisMesh_PRD.pdf`. 갱신 2026-10-06 (wds-implement 1~12차). 규제는 변하므로 출처로 재확인.
> 설계 참고용이며 법률 판단이 아니다. 적용 여부·의무 범위는 법무 검토 필요 (원본 PRD 부록 E).

## 분류

| 체계 | 코드 |
|---|---|
| KSIC | J (58, 59, 60, 61, 62, 63) |
| ISIC / NACE | J / J |
| NAICS | 51 |

## 한국 규제 (1순위)

| 규제 | 시행 | 영향 |
|---|---|---|
| 정보통신망법 | 현행 | 네트워크·정보보호 의무(§47 = ISMS 근거), 침해사고 신고 |
| 개인정보보호법(PIPA) | 현행 | PII 동의·최소화·유출통지(§32-2). AegisMesh 판정 페이로드에 원문 프롬프트 포함 → NFR-D1 원문 미보존 기본 |
| ISMS-P | 현행 (3년 주기) | 대형 ICT 서비스 의무. 접근로그·변경관리·암호화 증적 → 증적 원장(FR-P05)으로 자체 증적 확보 |
| CSAP (클라우드) | 2025 온라인 발급 | 공공/정부 클라우드 판매 시 IaaS/SaaS/DaaS 인증 |

PRD 추가 참조(§4.4): EU AI Act(Regulation (EU) 2024/1689), ISO/IEC 42001·23894, NIST AI RMF 1.0 / AI 600-1.

## 국제 기준

- SOC 2 Type II (US SaaS, 6~12개월 통제)
- ISO/IEC 27001 (SOC2 와 40~85% 통제 중첩)
- GDPR (EU 고객/테넌트)

## 데이터 등급

| 데이터 | 등급 | 비고 |
|---|---|---|
| 판정 페이로드(원문 프롬프트·응답) | 규제대상 (PRD NFR-S: 최고 등급) | 기본 미보존(NFR-D1), 보존 시 자동 마스킹, 보존 켜기는 2인 승인 |
| 테넌트 데이터 | 민감 | 고객별 격리(RLS/스키마/DB), FR-P13 |
| 고객 PII | 민감 | PIPA/GDPR, 기본 국내 처리(NFR-D5) |
| 인증/아이덴티티(RBAC) | 규제대상 | 접근통제, 워크로드 신원(FR-P07) |
| 감사로그/텔레메트리 | 내부 | SOC2/ISO 보관·삭제정책. 증적 원장 기본 90일 온라인, regulated-kr 5년 |
| 레드팀 공격 코퍼스 | 내부 (이중 용도 통제) | 별도 저장소·권한, 운영 클러스터 상주 금지(NFR-S, PRD §13.1) |

**규제대상 데이터는 local/prod 리허설을 포함한 비운영 환경에 실데이터 반입 금지.** 골든셋·공격셋은 합성 또는 공개 코퍼스만 사용.

## 인프라 패턴

- 멀티테넌트 격리(RLS/스키마/DB-per-tenant)
- 관측성(OTel 콜렉터 → 티어드 스토리지, 검증된 삭제 CC6.5/A.8.10). PRD: 수집 단계 마스킹(§12.5)
- 피처플래그, API 게이트웨이, 수평 오토스케일, 시크릿 관리
- 표준 CI/CD

stack_overrides 대비 현재 선택:

| 항목 | 도메인 권고 | 현재 스캐폴드 | 차이·근거 |
|---|---|---|---|
| backend | NestJS 또는 FastAPI, OpenAPI 계약 | FastAPI | 일치 |
| data | PostgreSQL + Prisma, Redis | PostgreSQL + SQLAlchemy/Alembic | ORM 만 상이(Python 프로파일 표준). 엔진 일치 |
| frontend | Next.js + TS + Tailwind/shadcn | Next.js 15 + TS + Tailwind 4 (`apps/web`) | 일치 (shadcn 대신 자체 컴포넌트 — 화면설계서 CMP 토큰) |
| observability | OpenTelemetry | OTel SDK(OTLP/HTTP) + Collector contrib 0.162 (compose `otel-collector`) | 수집 단계 마스킹(`observability/masking.yaml` → 생성 설정, 15th). 판정 traceId = trace id. 운영 백엔드는 exporters 에 추가 |
| 컴플라이언스 보고 | — | `/v1/reports/{pipa,eu-ai-act,owasp-llm-2026,owasp-asi-2026,nist-ai-rmf}` | 통제 카탈로그 `controls/*.yaml` + 매니페스트 standards 렌더. 법률 판단 아님 |
| 자체 점검 | — | `/v1/governance:assess` + worker 주기 | D10·X03·X08~X10 이 보존 기간·통제 매핑·원장 무결성·관측·사건 대응을 점검 |
| 멀티테넌트 격리 | RLS/스키마/DB-per-tenant | 앱 계층 강제 + PostgreSQL RLS(비특권 역할 `aegis_app`, FORCE) | 정책 네임스페이스·증적 체인 테넌트별, 교차 접근 매일 자동 시험 7항목(13th) |
| 시크릿 관리 | — | 내장 SPIFFE JWT-SVID 발급자 또는 **SPIRE**(`IDENTITY_BACKEND=spire`, Workload API·uid 증명·ES256, 53rd) + 동적 시크릿 임대 브로커(기본) · **OpenBao 임대 백엔드 선택**(`SECRETS_BACKEND=openbao`, 토큰 역할·브로커 정책 최소 권한, 41st · 운영형 raft·봉인 해제·설정 선언 감사 장치 리허설, 46th · **3노드 raft·transit 자동 봉인 해제·TLS 1.3 상호 인증**, 리더 장애 중 임대 실패 0, 56th) | SPIRE 연동 시 같은 계약으로 교체. OpenBao 운영 클러스터(봉인 해제·감사 장치)는 운영 절차. 키는 env(KMS) 주입, 미주입 시 볼륨 파일(리허설용) |
| 격리 실행 | — | L1 = 별도 프로세스·rlimit·Landlock·seccomp·감사 훅 · **L2 = gVisor runsc 고정 판 브로커**(compose sandbox-l2 — 비루트·능력 없음, 네트워크 없음·읽기 전용 루트 FS, 65th) | L3(microVM) 런타임 없음(KVM 없음) → 해당 에이전트 보류(격리 강등 금지). L2 탈출 점검 23/23 막힘 |
| 폐쇄망 | — | 서명 번들 + 내부 신뢰 저장소 + CycloneDX SBOM 취약점 기준 | 신뢰 키 추가·폐기 2인 승인, 무네트워크 검증(`aegis airgap verify`) |
| 사용자 인증 | SSO·MFA | 조직 SSO(OIDC 인가 코드 + PKCE, MFA acr/amr 필수, IdP 그룹→역할) + 비상 관리자만 비밀번호(사유·원장·알림) | 시험 IdP = 로컬 Keycloak 26.3(22nd). 클라이언트 비밀은 DB 에 두지 않음. 패스키·보안 키(WebAuthn) 2단계·OTP 대체, DPoP 세션 바인딩, 새 기기·위치 재인증, 탈취 토큰 재사용 → 세션 전체 폐기·사건(34th, Playwright 가상 인증기 E2E) · 특권 역할 2단계 강제·AAGUID 허용목록·IdP back-channel 로그아웃(38th) · 허용목록 = 제조사 증명 체인(MDS3, 자기 신고 AAGUID 불신, 54th) · 지오 IP 새 위치·불가능한 이동 → 재인증·D5-03 경보(55th) |
| 배포 | 표준 CI/CD, 수평 확장 | 헬름 차트(k3d 실제 설치 리허설) · compose · 단일 파일 CLI, 작업 프로세스 수 `WEB_CONCURRENCY` | 2→16 작업 1,776 rps(23rd) · 병목 3개 해결 뒤 공유 VM 최고 1,797 rps(66th, 리허설 값 — 2,000 확인은 전용 노드). 운영은 existingSecret·KMS 로 키 주입 |
| 재해 복구 | — | prod: WAL 보관(`archive_timeout` 60 s)·기본 백업 4시간·동기 대기 서버(원장 트랜잭션만 동기 커밋) · `make db-restore-drill`·`db-failover-drill` · **외부 복사**(S3·상호 TLS·파일마다 KMS 봉투 암호화, 52nd) | RTO 실측 38~138 s(목표 30분)·원장 RPO 0·일반 RPO ≤ 60 s (47th) · 객체 저장 복사본만으로 복구 RTO 93 s·평문 0 (52nd). 리허설 객체 저장은 같은 호스트 — 운영은 다른 사이트·외부 S3, builtin 키 고리는 따로 보관 |
| 전송 암호화 | — | prod 내부 4구간 상호 TLS — 실행 시 만든 내부 CA(볼륨 `tls`, 비커밋)·말단 90일·만료 30일 전 재발급·무중단 회전 | 평문·인증서 없는 접속 거부 확인(48th). K8s 는 서비스 메시·cert-manager 로 대체 |
| 저장 암호화 | — | 값 단위 봉투 암호화(AES-256-GCM DEK, KEK = OpenBao transit 또는 builtin 키 고리) — 원장·정책·프로파일·발견·승인·표본·OTP 비밀·서명 키 파일 | 덤프·WAL·백업 카나리 0(49th). 추가 전용 원장의 암호화 전 기록은 **통제된 재암호화**로 제거(2인 승인 창·서명 증명서, 해시 체인 불변 — 134만 건 → 0, VACUUM FULL 뒤 데이터 파일 평문 0, 57th). 키 고리·OpenBao 는 DB 백업과 따로 백업. 봉인 해제 HSM 경로 = PKCS#11(SoftHSM2 리허설, 비추출 키, 68th) |
| 판정 모델 (외부 가중치) | — | D1-03 깊은 검사 = Qwen3Guard-Gen-0.6B(Apache-2.0) 고정 커밋·가중치 해시를 이미지 빌드에서 검증, 실행 중 네트워크 없음·입력 미기록 · 인라인 = protectai/deberta-v3-base-prompt-injection-v2(Apache-2.0) 고정 커밋 ONNX sha256 검증(64th, 영어 — 라틴 문자 입력만) | 응답 뒤 경보 → 주체·세션 격리로 다음 요청부터 인라인 차단(해제 2인, 51st). 공개 코퍼스는 평가 전용 그대로(50th). 라이선스 고지는 이미지 /model/LICENSE |
| 외부 참조 데이터 (고정 판) | — | FIDO MDS3(보안 키 증명 근거 — GlobalSign R3 지문·서명자·CRL 검증, 54th) · DB-IP IP to City Lite(지오 IP, 월간 판 sha256 고정, 55th) — 둘 다 이미지 빌드에서만 받고 실행 중 네트워크 없음 | DB-IP Lite = CC BY 4.0 — 콘솔 계정 화면에 "IP Geolocation by DB-IP" 표기. MDS3 는 FIDO 이용 약관(BLOB legalHeader) 따름. 판 교체 = 재빌드 |
| 위치 정보 | 개인정보 최소 수집 | 세션에 IP 대역(/24·/48)·지오 표시(나라 · 시도)·좌표(소수 3자리)·마지막으로 본 시각만 — 원 IP 미저장 | 도시 수준 IP 위치는 단말 위치정보가 아님. 불가능한 이동 판단은 재인증·경보(차단 아님), 기록은 원장(암호화)·세션 수명 동안 (55th) |
| 에이전트 간 통신 | — | A2A v1.0 어댑터 — 서명 AgentCard(EdDSA JWS), 대역 밖 신뢰 키 고정, 호출자 JWT-SVID 검증 | X01 이 v1.0 카드 서명 검증(25th) |
| MCP 게이트웨이 | — | agentgateway v1.6.0(digest 고정) MCP 가드레일 → ExtMCP 정책 서버 → 도구·출력 관문(67th, local) | 정책 서버 장애 = 거부(failClosed), 원문 미보관 |
| 외부 연동 (SIEM·레드팀) | — | 발견 버스 NATS JetStream(요약만, 상호 TLS, 60th) · garak 0.13.1 어댑터(탐침별 공격 성공률만 원장, 페이로드 미보관, 59th) | 레드팀 엔진은 local 프로파일 전용(운영 클러스터 상주 금지, PRD §13.1) |
| 공급망 (폐쇄망) | — | 레지스트리 미러(registry 3.0.0 · crane 고정, digest 고정 이미지·OCI 헬름 차트, 61st) · 고정 판 갱신 `make pins-refresh`(58th) | 원 레지스트리 경로 없이 설치 확인 |

PRD 전용 인프라(`--extras` 범위 밖): ClickHouse(증적 원장), NATS(발견 버스), OPA(정책 결정점), OpenBao(시크릿 — Vault BUSL 회피). OpenTelemetry Collector 는 3차 실행에서 compose 서비스로 포함. 2026-10-06 결정으로 원장은 RDB 해시 체인, 정책은 내장 YAML 평가기로 시작하고 인터페이스를 분리해 두었다(교체 가능). 캐시 필요 시 Redis 대신 Valkey(BSD-3) 권장(PRD §10.12).

## 개발환경 특수 요구

- 테넌트 격리 테스트(크로스테넌트 누출 단언, RLS 강제)
- 표준 CI/CD(lint/type/test/build/deploy)
- 텔레메트리 보관/삭제 검증(CC6.5/A.8.10), OpenAPI 계약 테스트
- SOC2/ISO 통제 증적 자동화(접근로그·변경관리)
- PRD: 누락 검증(`verify_coverage.py`, FR-P16) CI 게이트 — 80 항목 대비 에이전트·요구사항·시험 누락 시 빌드 실패

## 추가 시험

구현 반영(2026-10-06): 해시 체인 무결성(`test/test_ledger.py`, impl 4th), 판정 설명 필드 100%·재현성(80종 품질 게이트), 교차 테넌트 데이터 혼입 탐지(D2-02·D5-02, impl 7th), 통제 보고서·보존 기간 점검(impl 11th), **크로스테넌트 누출 차단(RLS 강제·교차 조회 0건·범위 밖 INSERT 거부, `test/test_tenancy.py`, impl 13th)**, 접근로그·변경관리 원장 기록(로그인·역할 변경·토큰·신뢰 키·정책 배포·롤백 승인), 텔레메트리 수집 단계 마스킹(impl 15th), 격리 실행 탈출 점검(impl 17th), 서명 번들 반입·SBOM 취약점 기준(impl 18th), SSO·MFA·비상 관리자 봉인(impl 22nd), 증적 비동기 적재의 표본 강등 기록·대용량 원장 검증(impl 23rd·26th), 판정 이의 2인 결정·오탐 예산·골든셋·코퍼스 미탐률(impl 24th), 통제 보고서 영어(impl 26th). OpenAPI 계약 시험(스냅샷 대비 깨지는 변경 금지, `test/test_contract.py`)·감사로그 보관기간 경과 삭제 증명(2인 승인 배치·서명 증명서·법적 보존 제외, `test/test_retention.py`) — impl 37th.

**regulated-kr 운영 주의**: 증적 보존 1825일 요구 — `EVIDENCE_RETENTION_DAYS=1825` 로 설정하지 않으면 D10-02 가 차단(block) 판정을 낸다.

`test/dev-env`·`test/impl/<Nth>` 케이스로 반영:

- 크로스테넌트 데이터 누출 차단(RLS)
- OpenAPI 계약 적합성(contract test)
- 감사로그 보관기간 경과 삭제 증명
- 웹 접근성(KWCAG 2.2 / WCAG 2.2 AA 가정) — axe-core 자동 점검 전 경로 ko·en 위반 0·키보드(impl 39th) · 320px 재배치·글자 간격·글자 200% 잘림 0(impl 45th) (`make e2e-a11y`). 화면 낭독기 등 보조기술 실사용은 수동 점검 대상
- 공개 공격 코퍼스 미탐률(NFR-Q2) — 고정 판 JailbreakBench·garak·HarmBench·XSTest·GSM8K 실측(`make corpus-eval`, impl 43rd): 주입·탈옥 미탐 41.1% 로 목표(≤ 10%) **미달**, 정상 오탐 0.1~0.4%. 페이로드 미보존·평가 전용
- PRD: 증적 해시 체인 무결성 검증 100%, 판정 설명 필드(rule_id·evidence·confidence) 100%, 동일 입력 판정 재현성

## 출처

- https://isms-p.or.kr/sysm/intro/selectSysmCertDetail.do (ISMS-P)
- https://isms.kisa.or.kr/main/csap/notice/ (CSAP 2025)
- https://secureframe.com/blog/soc-2-vs-iso-27001
- https://oneuptime.com/blog/post/2026-02-06-telemetry-retention-soc2-iso27001/view
- https://www.ideadope.com/roadmaps/how-to-build-multi-tenant-saas-2025
- `.docs/AegisMesh_PRD.pdf` §4.4, §7.5, §7.7, §12.5–12.6, §13
