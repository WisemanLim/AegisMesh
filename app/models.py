"""핵심 엔티티 (PRD §12.2). SQLite·PostgreSQL 공용 타입만 사용."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.kms import EncryptedJSON, EncryptedText


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RiskItem(Base):
    """도식 원본 항목(D1-01…D10-07) + 보강(X01…X10). Agent 와 1:1 — 누락 검증의 기준."""
    __tablename__ = "risk_items"
    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))                    # item | gap
    domain: Mapped[str | None] = mapped_column(String(4))
    name_en: Mapped[str] = mapped_column(String(80))
    name_ko: Mapped[str] = mapped_column(String(80))
    priority: Mapped[str] = mapped_column(String(2))
    series: Mapped[str] = mapped_column(String(2))
    stage: Mapped[int] = mapped_column(Integer)
    fr: Mapped[str] = mapped_column(String(16))


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    item_id: Mapped[str] = mapped_column(ForeignKey("risk_items.id"), unique=True)
    version: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(120))
    name_ko: Mapped[str] = mapped_column(String(120))
    series: Mapped[str] = mapped_column(String(2))
    gate: Mapped[str] = mapped_column(String(10))
    isolation: Mapped[str] = mapped_column(String(2))
    fail_mode: Mapped[str] = mapped_column(String(6))
    latency_budget_ms: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="active")   # active|review_pending|alert_only|stopped
    origin: Mapped[str] = mapped_column(String(8), default="builtin")   # builtin|api
    manifest: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Policy(Base):
    """선언형 정책 — 버전을 남긴다(DP6). 수정 대신 새 버전 추가. 테넌트별 네임스페이스(FR-P13) — 테넌트 간 공유 없음."""
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("tenant", "policy_id", "version"),)
    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant: Mapped[str] = mapped_column(String(32), index=True, default="default")
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer)
    body: Mapped[dict] = mapped_column(EncryptedJSON("policies.body"))
    created_by: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Profile(Base):
    """내장 프로파일(tenant 없음 — 모든 테넌트 공유) + 테넌트 사용자 정의 프로파일(SCR-C08, id = <tenant>.<id>)."""
    __tablename__ = "profiles"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name_ko: Mapped[str] = mapped_column(String(120))
    spec: Mapped[dict] = mapped_column(EncryptedJSON("profiles.spec"))
    tenant: Mapped[str | None] = mapped_column(String(32), index=True)
    created_by: Mapped[str | None] = mapped_column(String(64))


class ProfileApplication(Base):
    """즉시 사용 적용 — 테넌트·대상별 활성 1건. 관문 바인딩의 원천."""
    __tablename__ = "profile_applications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("profiles.id"))
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(200))
    stage: Mapped[str] = mapped_column(String(8))                    # observe|partial|enforce
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    agent_ids: Mapped[list] = mapped_column(JSON)
    missing: Mapped[list] = mapped_column(JSON)
    applied_by: Mapped[str] = mapped_column(String(64))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(8), index=True)
    gate: Mapped[str] = mapped_column(String(10))
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(8))
    confidence: Mapped[float] = mapped_column(Float)
    rule_id: Mapped[str] = mapped_column(String(64))
    valid: Mapped[bool] = mapped_column(Boolean)
    degraded: Mapped[bool] = mapped_column(Boolean)
    body: Mapped[dict] = mapped_column(EncryptedJSON("findings.body"))                          # Finding/v1 (원문·무해화 결과 제외)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant: Mapped[str] = mapped_column(String(64))
    gate: Mapped[str] = mapped_column(String(10))
    finding_ids: Mapped[list] = mapped_column(JSON)
    summary: Mapped[str] = mapped_column(EncryptedText("approvals.summary", None))
    requested_by: Mapped[str] = mapped_column(String(64))
    required: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    action: Mapped[dict | None] = mapped_column(JSON)     # 승인 완료 시 실행할 행동(정책 롤백 등). 관문 승인은 없음
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # 만료 시 자동 거절 (SCR-O06)


class ApprovalDecision(Base):
    __tablename__ = "approval_decisions"
    __table_args__ = (UniqueConstraint("approval_id", "principal"),)
    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    approval_id: Mapped[str] = mapped_column(ForeignKey("approvals.id"), index=True)
    principal: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(8))                  # approve|reject
    reason: Mapped[str] = mapped_column(EncryptedText("approval_decisions.reason", None))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Evidence(Base):
    """추가 전용 증적 원장 (DP9). UPDATE·DELETE 는 DB 트리거가 거부한다."""
    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_chain_seq", "chain", "seq"),)
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(32), unique=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)        # finding|gate|approval|policy|profile|agent
    ref_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    body: Mapped[dict] = mapped_column(EncryptedJSON("evidence.body"))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[str] = mapped_column(String(32))              # ISO 문자열 — 해시 입력과 동일 표현
    chain: Mapped[str] = mapped_column(String(32), default="legacy")  # 해시 체인 = 테넌트(FR-P13). legacy = 0006 이전 단일 체인


class LedgerCheckpoint(Base):
    __tablename__ = "ledger_checkpoints"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    chain: Mapped[str] = mapped_column(String(32), default="legacy")
    hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[str] = mapped_column(String(32))


class LedgerPurge(Base):
    """보존기한 만료 삭제 증명 (NFR-S·R07) — 2인 승인 배치가 서명 체크포인트까지 지운 구간과 서명 증명서. 추가 전용.
    이 행이 있어야 DB 트리거가 그 구간(체인·through_seq 이하)의 evidence DELETE 를 허용한다."""
    __tablename__ = "ledger_purges"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    chain: Mapped[str] = mapped_column(String(32), index=True)
    through_seq: Mapped[int] = mapped_column(Integer)
    anchor_hash: Mapped[str] = mapped_column(String(64))            # 지운 마지막 레코드(= 서명 체크포인트)의 해시 — 남은 체인의 시작 prevHash
    records: Mapped[int] = mapped_column(Integer)
    certificate: Mapped[dict] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[str] = mapped_column(String(32))


class LedgerRewrap(Base):
    """원장 저장 재암호화 창 (Epic 57 · NFR-D2) — 2인 승인으로 연 seq 구간·만료 시각과 서명 증명서. 추가 전용.
    이 행이 살아 있는 동안만 DB 트리거가 그 구간 evidence 의 '평문 → 봉투 암호문(다른 열 불변)' 갱신을 허용한다."""
    __tablename__ = "ledger_rewraps"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    from_seq: Mapped[int] = mapped_column(Integer)
    through_seq: Mapped[int] = mapped_column(Integer)
    expires_epoch: Mapped[int] = mapped_column(Integer)             # 유닉스 초 — 두 엔진 트리거가 같은 비교를 하도록
    records: Mapped[int] = mapped_column(Integer)
    certificate: Mapped[dict] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[str] = mapped_column(String(32))


class BusCursor(Base):
    """발견 버스 중계 커서 (Epic 60) — 원장 seq 를 어디까지 NATS JetStream 에 게시·확인 받았는지."""
    __tablename__ = "bus_cursors"
    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer)


class LedgerHead(Base):
    """0006 이전 단일 체인(legacy)의 머리 — 동결. 새 적재는 LedgerChain(테넌트별)."""
    __tablename__ = "ledger_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    hash: Mapped[str] = mapped_column(String(64))


class LedgerChain(Base):
    """테넌트별 체인 머리 (FR-P13 증적 파티션). 적재 시 행 잠금으로 체인 분기를 막는다."""
    __tablename__ = "ledger_chains"
    chain: Mapped[str] = mapped_column(String(32), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)            # 마지막 레코드의 전역 seq
    hash: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer, default=0)


class ScanTarget(Base):
    """상시 점검 대상 (C3) — MCP 서버·플러그인·SBOM·IaC·로그 파이프라인 등. worker 가 주기 실행."""
    __tablename__ = "scan_targets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(200))
    artifact: Mapped[dict] = mapped_column(JSON)
    interval_sec: Mapped[int] = mapped_column(Integer, default=3600)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verdict: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Quarantine(Base):
    """상시 점검 발견으로 인라인 정책을 동적으로 바꾼 기록 (PRD §8.2) — 도구 관문이 즉시 참조한다."""
    __tablename__ = "quarantine"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32))                     # mcp_server|plugin|skill|tool|agent|principal|session
    value: Mapped[str] = mapped_column(String(200), index=True)
    reason: Mapped[str] = mapped_column(Text)
    finding_ids: Mapped[list] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    released_by: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # 깊은 검사 격리(주체·세션)의 기한 — 비우면 무기한


class PublisherKey(Base):
    """등록 심사 R2 — 신뢰하는 에이전트 게시자 서명키(Ed25519 공개키)."""
    __tablename__ = "publisher_keys"
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    public_key: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    added_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    tier: Mapped[str] = mapped_column(String(10), default="community")   # official|partner|community (장터 신뢰 등급)


class AgentReview(Base):
    """등록 7단계 심사 기록(R1~R5) — 번들 해시 단위. 결과는 원장에도 남는다."""
    __tablename__ = "agent_reviews"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(8), index=True)
    version: Mapped[str] = mapped_column(String(32))
    bundle_sha256: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16))        # active|alert_only|review_hold|rejected
    stages: Mapped[dict] = mapped_column(JSON)
    submitted_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    """상관 분석으로 묶인 사건 (FR-P06) — 같은 원인(테넌트·주체/대상·도메인)이 시간 창 안에서 반복되면 한 사건."""
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    key: Mapped[str] = mapped_column(String(200), index=True)
    title: Mapped[str] = mapped_column(String(200))
    domain: Mapped[str] = mapped_column(String(4))
    severity: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(8), default="open", index=True)   # open|closed
    contained: Mapped[bool] = mapped_column(Boolean, default=False)
    trace_ids: Mapped[list] = mapped_column(JSON)
    finding_ids: Mapped[list] = mapped_column(JSON)
    agent_ids: Mapped[list] = mapped_column(JSON)
    rule_ids: Mapped[list] = mapped_column(JSON)
    finding_total: Mapped[int] = mapped_column(Integer, default=0)          # trace_ids·finding_ids 는 최근 KEEP 건만 보관
    trace_total: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_by: Mapped[str | None] = mapped_column(String(64))


class Risk(Base):
    """위험 등록부 (FR-D10-03, SCR-N03) — 결정은 수정 대신 새 상태로 갱신하고 원장에 남긴다."""
    __tablename__ = "risks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    score: Mapped[float | None] = mapped_column(Float)
    decision: Mapped[str] = mapped_column(String(12), default="open")    # mitigate|accept|transfer|avoid|open
    owner: Mapped[str | None] = mapped_column(String(64))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(8), default="open")
    source: Mapped[str | None] = mapped_column(String(64))              # finding·incident·build gate 참조
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Tenant(Base):
    """테넌트 (FR-P13, SCR-R01) — 정책 네임스페이스·증적 체인·인덱스/캐시 접두 = 테넌트 ID."""
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    isolation: Mapped[str] = mapped_column(String(10), default="logical")     # logical (physical = 전용 설치)
    retention_days: Mapped[int] = mapped_column(Integer, default=90)
    region: Mapped[str] = mapped_column(String(16), default="kr")
    lang: Mapped[str] = mapped_column(String(2), default="ko")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    sample_retention: Mapped[dict | None] = mapped_column(JSON)          # 미리보기 표본 보존 {enabled, maxSamples, days} — 2인 승인(OQ1)
    auth_policy: Mapped[dict | None] = mapped_column(JSON)               # 로그인 정책 {mfa: privileged|all, aaguids: [...]} (OQ3)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrafficSample(Base):
    """미리보기용 실제 트래픽 표본 (OQ1·NFR-D1) — 테넌트가 켠 경우에만, 수집 단계에서 마스킹한 요청 모양. N건·기한 뒤 삭제."""
    __tablename__ = "traffic_samples"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    gate: Mapped[str] = mapped_column(String(10))
    target: Mapped[str | None] = mapped_column(String(120))
    profile: Mapped[str | None] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))
    request: Mapped[dict] = mapped_column(EncryptedJSON("traffic_samples.request"))
    masked: Mapped[list] = mapped_column(JSON, default=list)                 # 적용된 마스킹 규칙 이름
    label: Mapped[str | None] = mapped_column(String(8))                     # benign|attack — 미리보기 오탐·미탐 추정용
    labeled_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class User(Base):
    """콘솔·API 사용자 (SCR-R02). tenant 가 없으면 플랫폼 사용자(모든 테넌트). kind=service 는 판정 호출용 서비스 계정."""
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str | None] = mapped_column(String(255))           # None = 비밀번호 로그인 불가(서비스·OIDC)
    roles: Mapped[list] = mapped_column(JSON)
    tenant: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(8), default="human")             # human|service
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)
    external_id: Mapped[str | None] = mapped_column(String(255), index=True, unique=True)  # 조직 SSO 신원 <iss>#<sub> (비밀번호 없음)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_secret: Mapped[str | None] = mapped_column(EncryptedText("users.totp_secret"))   # 인증 앱 OTP 비밀(KMS 봉투 암호화, NFR-D2) — 2단계 대체 수단
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int | None] = mapped_column(Integer)                 # 같은 OTP 재사용 방지
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthSession(Base):
    """로그인 세션·API 토큰·부트스트랩 토큰. 토큰 = am1.<id>.<HMAC 서명> — DB 에는 id 만(서명은 서버 비밀로만 재현)."""
    __tablename__ = "auth_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(12))                             # session|api_token|bootstrap
    name: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    jkt: Mapped[str | None] = mapped_column(String(64))                        # DPoP 키 지문 — 있으면 모든 요청에 소유 증명 필수 (FR-D5-03)
    mfa: Mapped[str | None] = mapped_column(String(16))                        # webauthn|totp|sso|none — 로그인 2단계 수단
    device: Mapped[str | None] = mapped_column(String(120))                    # 기기 표시(브라우저·OS 계열) — 원 UA 아님
    device_hash: Mapped[str | None] = mapped_column(String(16))
    location: Mapped[str | None] = mapped_column(String(64))                   # 위치 = IP 대역(/24·/48) — 정밀 위치 아님
    geo: Mapped[str | None] = mapped_column(String(80))                        # 지오 IP 표시 "KR · Seoul" | private | unknown (Epic 55, 도시 수준)
    geo_lat: Mapped[float | None] = mapped_column(Float)
    geo_lon: Mapped[float | None] = mapped_column(Float)
    geo_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # 그 지점에서 마지막으로 본 시각(30초 단위) — 이동 속도 기준
    state: Mapped[str] = mapped_column(String(12), default="ok")               # ok|review(새 기기·위치 → 재인증 전까지 제한)
    review_reason: Mapped[str | None] = mapped_column(String(200))


class WebAuthnCredential(Base):
    """패스키·보안 키 (SCR-B02 2단계) — 공개키(COSE)·서명 카운터만. 개인키는 인증기 밖으로 나오지 않는다."""
    __tablename__ = "webauthn_credentials"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)             # credential ID (base64url)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    public_key: Mapped[str] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(120), default="")
    alg: Mapped[str] = mapped_column(String(8))
    aaguid: Mapped[str | None] = mapped_column(String(32))
    transports: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MfaChallenge(Base):
    """WebAuthn challenge · 로그인 2단계 대기표 — 1회용, 5분."""
    __tablename__ = "mfa_challenges"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(12))                           # login|register|reauth
    challenge: Mapped[str] = mapped_column(String(128))
    jkt: Mapped[str | None] = mapped_column(String(64))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DpopJti(Base):
    """사용한 DPoP 증명 jti — 허용 오차(60초) 동안만 기억해 증명 재사용을 막는다."""
    __tablename__ = "dpop_jti"
    id: Mapped[str] = mapped_column(String(96), primary_key=True)              # <jkt 앞 16자>:<jti>
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class WorkloadIdentity(Base):
    """워크로드 신원 (FR-P07, SPIFFE) — 에이전트·플랫폼 구성요소·서비스 계정. 토큰(JWT-SVID) 자체는 저장하지 않고 jti·만료만."""
    __tablename__ = "workload_identities"
    spiffe_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))                     # agent|platform|service
    ref: Mapped[str] = mapped_column(String(64), index=True)
    tenant: Mapped[str | None] = mapped_column(String(32))
    ttl_sec: Mapped[int] = mapped_column(Integer)
    jti: Mapped[str | None] = mapped_column(String(32))
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # 이 시각 이전 발급 SVID 전부 무효(즉시 회전)
    rotations: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(10), default="active")  # active|revoked
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecretLease(Base):
    """동적 시크릿 임대 (FR-P07) — 호출 단위·최소 범위·짧은 수명. 시크릿 원문은 해시만 보관."""
    __tablename__ = "secret_leases"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(32), index=True)
    path: Mapped[str] = mapped_column(String(120))
    scopes: Mapped[list] = mapped_column(JSON)
    holder: Mapped[str] = mapped_column(String(200))
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    renewals: Mapped[int] = mapped_column(Integer, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))
    backend: Mapped[str] = mapped_column(String(16), default="builtin", server_default="builtin")   # builtin | openbao (Epic 41)
    accessor: Mapped[str | None] = mapped_column(String(64))       # OpenBao 토큰 접근자 — 조회·갱신·회수용(시크릿 아님)


class TrustKey(Base):
    """내부 신뢰 저장소 (FR-P14, NFR-C3) — 폐쇄망 번들 서명 검증 키. 추가·폐기는 2인 승인."""
    __tablename__ = "trust_keys"
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    public_key: Mapped[str] = mapped_column(String(64))
    purpose: Mapped[str] = mapped_column(String(16), default="bundle")
    status: Mapped[str] = mapped_column(String(10), default="pending")      # pending|active|revoked
    added_by: Mapped[str] = mapped_column(String(64))
    approval_id: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BundleImport(Base):
    """폐쇄망 번들 반입 기록 — 단계별 검증 결과와 적용 내역."""
    __tablename__ = "bundle_imports"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    version: Mapped[str | None] = mapped_column(String(40))
    sha256: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(12))                         # imported|rejected
    steps: Mapped[list] = mapped_column(JSON)
    applied: Mapped[dict] = mapped_column(JSON)
    imported_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MarketListing(Base):
    """장터 (SCR-C10) — 반입·제출된 서드파티 에이전트. 설치 = 2인 승인 후 등록 심사(R1~R5)."""
    __tablename__ = "market_listings"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)          # <agent>@<version>
    agent_id: Mapped[str] = mapped_column(String(8))
    version: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(120))
    name_ko: Mapped[str] = mapped_column(String(120))
    item_id: Mapped[str] = mapped_column(String(8))
    publisher: Mapped[str | None] = mapped_column(String(64))
    tier: Mapped[str] = mapped_column(String(10))                           # official|partner|community|external
    license: Mapped[str] = mapped_column(String(120))
    isolation: Mapped[str] = mapped_column(String(2))
    bundle: Mapped[dict] = mapped_column(JSON)
    bundle_sha256: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(40))                         # bundle:<import id>
    status: Mapped[str] = mapped_column(String(12), default="available")    # available|requested|installed|hold|rejected
    review_id: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SsoConfig(Base):
    """조직 SSO(OIDC) 설정 (SCR-A06) — 1행(default). 클라이언트 비밀은 DB 에 두지 않는다(OIDC_CLIENT_SECRET, 공개 클라이언트+PKCE 기본)."""
    __tablename__ = "sso_config"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(120))
    groups_claim: Mapped[str] = mapped_column(String(64), default="groups")
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=True)
    acr_values: Mapped[list] = mapped_column(JSON)                          # MFA 로 인정할 acr (요청 acr_values 로도 보냄)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SsoGroupMap(Base):
    """IdP 그룹 → 역할 매핑 (SCR-A06·R02). tenant 가 없으면 플랫폼 사용자. 매핑 없는 사용자는 로그인 거부."""
    __tablename__ = "sso_group_maps"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group: Mapped[str] = mapped_column(String(120), index=True)
    role: Mapped[str] = mapped_column(String(32))
    tenant: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OidcRequest(Base):
    """진행 중인 OIDC 인가 요청 — state 1회용, PKCE code_verifier·nonce 는 서버에만 (10분)."""
    __tablename__ = "oidc_requests"
    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    verifier: Mapped[str] = mapped_column(String(128))
    redirect_uri: Mapped[str] = mapped_column(String(255))
    next: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingLabel(Base):
    """판정 이의·라벨 (SCR-O02, NFR-Q6) — 접수 → (재현 표본 교차 판정) → 다른 사람이 결정(fp|tp). fp 확정은 오탐 예산에 집계."""
    __tablename__ = "finding_labels"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(8), index=True)
    gate: Mapped[str] = mapped_column(String(8))
    verdict: Mapped[str] = mapped_column(String(20))                       # 이의 당시 유효 판정
    confidence: Mapped[float] = mapped_column(Float)
    rule_id: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(String(20))                         # false_positive|wrong_rule|other
    detail: Mapped[str] = mapped_column(String(500))
    method: Mapped[str] = mapped_column(String(10))                         # human|rejudge
    status: Mapped[str] = mapped_column(String(10), default="received")     # received|decided
    label: Mapped[str | None] = mapped_column(String(4))                    # fp|tp
    rejudge: Mapped[dict | None] = mapped_column(JSON)
    sample_id: Mapped[str | None] = mapped_column(String(32))
    requested_by: Mapped[str] = mapped_column(String(64))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(64))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    note: Mapped[str | None] = mapped_column(String(300))


class GoldenSample(Base):
    """골든셋 편입 표본 — 이의에서 오탐으로 확정되고 신청자가 마스킹한 재현 표본을 제공한 경우만(원문 자동 보존 없음, NFR-D1)."""
    __tablename__ = "golden_samples"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    gate: Mapped[str] = mapped_column(String(8))
    agent_id: Mapped[str | None] = mapped_column(String(8))
    request: Mapped[dict] = mapped_column(EncryptedJSON("golden_samples.request"))
    source: Mapped[str] = mapped_column(String(40))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProtectedTarget(Base):
    """보호 대상 (SCR-C05) — 프로파일을 거는 서비스·엔드포인트와 관문 삽입 방식·모델 공급자·MCP 서버·이그레스 허용목록."""
    __tablename__ = "protected_targets"
    __table_args__ = (UniqueConstraint("tenant", "name"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(32))                      # chatbot|coding_agent|workflow|rag|other
    endpoint: Mapped[str] = mapped_column(String(300))
    insertion: Mapped[str] = mapped_column(String(16))                  # gateway|sidecar|sdk
    model_provider: Mapped[str] = mapped_column(String(200))            # 자체 호스팅 엔드포인트 또는 외부 공급자
    external_model: Mapped[bool] = mapped_column(Boolean, default=False)
    mcp_servers: Mapped[list] = mapped_column(JSON)                     # [name]
    egress: Mapped[list] = mapped_column(JSON)                          # [{host, pin}]
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
