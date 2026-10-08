"""AegisMesh 공통 스키마 — JudgeRequest(입력) · Decision(core 반환) · Finding(판정 단일 표현, PRD §12.1)."""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Verdict = Literal["allow", "block", "require_approval", "transform", "alert"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Gate = Literal["input", "tool", "output", "evidence", "offline"]

# 제한 강도 순서 — 관문 합성 시 가장 강한 판정이 이긴다
VERDICT_RANK: dict[str, int] = {"allow": 0, "alert": 1, "transform": 2, "require_approval": 3, "block": 4}


class _Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class Principal(_Model):
    type: Literal["user", "agent", "service"] = "user"
    id: str
    roles: list[str] = []
    scopes: list[str] = []
    spiffe_id: str | None = Field(None, alias="spiffeId")


class Subject(_Model):
    tenant: str = "default"
    principal: Principal | None = None
    on_behalf_of: Principal | None = Field(None, alias="onBehalfOf")
    resource: dict[str, str] | None = None
    # 공정성 집계용 집단 라벨 (FR-D10-05) — 가명·범주 값만(예 {"age": "20s", "lang": "foreign", "region": "metro", "channel": "app"}).
    # 개인 식별 값을 넣지 않도록 키·값 모양과 개수를 제한한다.
    groups: dict[str, str] | None = None

    @field_validator("groups")
    @classmethod
    def _groups(cls, v):
        if v is None:
            return v
        if len(v) > 8:
            raise ValueError("groups: 축 8개 이하")
        for k, x in v.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,15}", k) or not re.fullmatch(r"[\w+.-]{1,24}", x):
                raise ValueError(f"groups: 범주 라벨만 (키 소문자 16자·값 24자) — {k!r}")
        return v


class Segment(_Model):
    """컨텍스트 조각. trust=untrusted 는 웹·문서·도구 응답 등 외부 출처."""
    source: str = "user"
    trust: Literal["trusted", "untrusted"] = "trusted"
    text: str


class ToolCall(_Model):
    name: str
    args: dict[str, Any] = {}
    required_scopes: list[str] = Field([], alias="requiredScopes")
    approved: bool = False


class Auth(_Model):
    method: Literal["none", "basic", "api_key", "password", "oauth", "mtls", "spiffe"] = "none"
    mfa: bool = False
    token_claims: dict[str, Any] | None = Field(None, alias="tokenClaims")
    signed_identity: bool = Field(False, alias="signedIdentity")
    attested_spiffe_id: str | None = Field(None, alias="attestedSpiffeId")


class Session(_Model):
    id: str
    bound_fingerprint: str | None = Field(None, alias="boundFingerprint")
    fingerprint: str | None = None
    bound_ip: str | None = Field(None, alias="boundIp")
    ip: str | None = None
    bound_key: str | None = Field(None, alias="boundKey")      # 세션이 묶인 소유 증명 키 지문(DPoP jkt · mTLS x5t)
    proof_key: str | None = Field(None, alias="proofKey")      # 이 요청이 제시한 증명 키 지문(없으면 증명 없음)
    travel_km: float | None = Field(None, alias="travelKm")     # 마지막으로 본 지점 → 지금 지점 대권 거리(지오 IP, Epic 55)
    travel_kmh: float | None = Field(None, alias="travelKmh")   # 그 사이 속도 — 불가능한 이동 판단 근거


class RetrievedDoc(_Model):
    """검색·도구 결과로 컨텍스트에 들어온 문서 (D2-04·D8·D4 근거성)."""
    id: str
    source: str = "index"
    text: str = ""
    url: str | None = None
    tenant: str | None = None
    owner: str | None = None
    acl: list[str] | None = None                    # 허용 주체 ID 또는 "role:<역할>". None = 공개
    signed: bool | None = None
    trust: Literal["trusted", "untrusted"] = "untrusted"


class MemoryRecord(_Model):
    """장기 메모리 레코드 (D2-07·D8)."""
    id: str
    text: str = ""
    tenant: str | None = None
    owner: str | None = None
    session: str | None = None
    writer: str | None = None
    created_at: float | None = Field(None, alias="createdAt")   # epoch 초
    ttl_sec: int | None = Field(None, alias="ttlSec")
    checksum: str | None = None
    approved: bool | None = None


class PlannedAction(_Model):
    """에이전트가 실행하려는 행동의 영향 정보 (D4-03·D6)."""
    type: str
    impact: Literal["low", "medium", "high", "critical"] = "low"
    external: bool = False
    reversible: bool = True
    amount: float | None = None
    currency: str | None = None
    confidence: float | None = Field(None, ge=0, le=1)
    grounded: bool | None = None
    approved: bool = False


class JudgeRequest(_Model):
    """에이전트 입력. 원문은 판정에만 쓰이고 저장되지 않는다(NFR-D1)."""
    schema_: Literal["aegismesh.io/JudgeRequest/v1"] = Field("aegismesh.io/JudgeRequest/v1", alias="schema")
    trace_id: str | None = Field(None, alias="traceId")
    gate: Gate | None = None
    subject: Subject = Subject()
    text: str | None = None                        # 사용자 입력 원문
    segments: list[Segment] = []                   # 조립된 컨텍스트
    system: str | None = None                      # 시스템 지시(숨은 컨텍스트)
    output: str | None = None                      # 모델 출력
    goal: str | None = None                        # 원래 과업 목표
    plan: list[str] = []                           # 에이전트 계획 단계
    tool: ToolCall | None = None
    auth: Auth | None = None
    session: Session | None = None
    retrieval: list[RetrievedDoc] = []             # 검색 결과 문서
    memory: list[MemoryRecord] = []                # 장기 메모리
    action: PlannedAction | None = None            # 실행하려는 행동
    history: list[dict[str, Any]] = []             # 직전 실행 단계 {tool, args, stateHash, agent, depth}
    artifact: dict[str, Any] | None = None         # 상시 점검 대상 {kind: sbom|iac|mcp_server|model|log_pipeline|…}
    params: dict[str, Any] = {}                    # 조직별 설정(허용목록·한도 등)

    def texts(self, *fields: str) -> list[tuple[str, str]]:
        """(위치 라벨, 텍스트) 목록. fields 미지정 시 입력 계열 전체."""
        fields = fields or ("text", "segments", "system", "output")
        out: list[tuple[str, str]] = []
        for f in fields:
            if f == "segments":
                out += [(f"segments[{i}]", s.text) for i, s in enumerate(self.segments)]
            elif (v := getattr(self, f)) :
                out.append((f, v))
        return out


class EvidenceItem(_Model):
    kind: str
    note: str
    location: str | None = None
    offset: int | None = None
    length: int | None = None


class Decision(_Model):
    """core.detect 의 반환값 — 순수 판정. 신원·표준·시간은 SDK 가 덧붙인다."""
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity = "info"
    rule_id: str = Field(alias="ruleId")
    evidence: list[EvidenceItem] = []
    transform: str | None = None                   # verdict=transform 일 때 무해화 결과


class AgentRef(_Model):
    id: str
    version: str
    engine: str


class Action(_Model):
    taken: Literal["none", "blocked", "transformed", "pending_approval", "alerted", "allowed"] = "none"
    transform: str | None = None
    approval_ref: str | None = Field(None, alias="approvalRef")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Finding(_Model):
    schema_: Literal["aegismesh.io/Finding/v1"] = Field("aegismesh.io/Finding/v1", alias="schema")
    id: str = Field(default_factory=lambda: new_id("fnd"))
    trace_id: str = Field(default_factory=lambda: secrets.token_hex(16), alias="traceId")
    span_id: str = Field(default_factory=lambda: secrets.token_hex(8), alias="spanId")
    agent: AgentRef
    subject: Subject = Subject()
    gate: Gate
    verdict: Verdict
    confidence: float
    severity: Severity
    rule_id: str = Field(alias="ruleId")
    evidence: list[EvidenceItem]
    standards: dict[str, Any]
    action: Action = Action()
    latency_ms: float = Field(alias="latencyMs")
    payload_ref: str | None = Field(None, alias="payloadRef")   # 원문 자체는 절대 담지 않는다
    valid: bool = True                                          # DP3: 근거·표준 누락 시 False
    invalid_reason: str | None = Field(None, alias="invalidReason")
    degraded: bool = False                                      # 타임아웃·오류로 failMode 적용
    occurred_at: str = Field(default_factory=now_iso, alias="occurredAt")

    def dump(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, mode="json")
