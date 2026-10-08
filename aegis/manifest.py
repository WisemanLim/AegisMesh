"""agent.yaml 규격 (PRD §11.2) — 등록 R1 단계의 스키마 검증 기준."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.schemas import Gate, Verdict

ISOLATION_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
SERIES_FAIL_DEFAULT = {"C1": "closed", "C2": "closed", "C3": "open", "C4": "open"}  # NFR-A3
ID_RE = re.compile(r"^(d(10|[1-9])-0[1-7]|x(0[1-9]|10))$")


class _M(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class Source(_M):
    diagram: str
    domain: str
    item: str


class Metadata(_M):
    id: str
    name: str
    name_ko: str = Field(alias="nameKo")
    version: str
    source: Source

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ID_RE.match(v):
            raise ValueError("id 는 도식 항목 ID(d1-01…d10-07, x01…x10) 소문자여야 한다")
        return v


class StandardRef(_M):
    version: str = Field(min_length=1)          # DP7: 판본 필수
    ids: list[str]


class EngineDef(_M):
    id: str
    kind: Literal["builtin", "external"]
    repo: str | None = None
    license: str | None = None
    invoke: dict[str, Any] | None = None


class Engines(_M):
    default: str
    available: list[EngineDef]

    @model_validator(mode="after")
    def _default_listed(self):
        if self.default not in {e.id for e in self.available}:
            raise ValueError(f"engines.default '{self.default}' 가 available 에 없다")
        return self


class Tests(_M):
    golden: str
    attacks: str
    baseline: str
    thresholds: dict[str, float] = {"falsePositiveRate": 0.005, "falseNegativeRate": 0.10}


class ConfigParam(_M):
    """조직이 정책으로 정하는 설정 파라미터(허용목록·한도·임계) — 플랫폼 관문에서는 정책 값이 요청 값보다 우선한다.
    default 는 엔진 기본값의 표시용 사본(정책에 값이 없으면 엔진 기본값이 쓰인다)."""
    type: Literal["string", "number", "integer", "boolean", "list", "map", "json"]
    default: Any = None
    items: Literal["string", "integer", "number"] | None = None     # list 원소 형
    min: float | None = None
    max: float | None = None
    enum: list[Any] | None = None
    label_ko: str = Field(alias="labelKo", min_length=1)
    label_en: str = Field(alias="labelEn", min_length=1)


def check_param(p: ConfigParam, v: Any) -> str | None:
    """값 하나를 선언과 대조. 문제 없으면 None, 있으면 사유."""
    num = isinstance(v, (int, float)) and not isinstance(v, bool)
    if p.type == "string" and not isinstance(v, str):
        return "문자열이어야 한다"
    if p.type == "number" and not num:
        return "숫자여야 한다"
    if p.type == "integer" and not (num and float(v).is_integer()):
        return "정수여야 한다"
    if p.type == "boolean" and not isinstance(v, bool):
        return "true/false 여야 한다"
    if p.type == "list":
        if not isinstance(v, list):
            return "목록이어야 한다"
        if len(v) > 1000:
            return "목록은 1000개 이하"
        want = {"string": str, "integer": int, "number": (int, float)}.get(p.items or "")
        if want and any(not isinstance(x, want) or isinstance(x, bool) for x in v):
            return f"목록 원소는 {p.items} 여야 한다"
    if p.type == "map" and not isinstance(v, dict):
        return "키-값 객체여야 한다"
    if p.type == "json" and not isinstance(v, (dict, list)):
        return "JSON 객체·목록이어야 한다"
    if num and p.min is not None and v < p.min:
        return f"{p.min} 이상"
    if num and p.max is not None and v > p.max:
        return f"{p.max} 이하"
    if p.enum is not None and v not in p.enum:
        return f"허용 값 {p.enum}"
    return None


class Spec(_M):
    series: Literal["C1", "C2", "C3", "C4"]
    gate: Gate
    isolation: Literal["L0", "L1", "L2", "L3"]
    verdicts: list[Verdict]
    latency_budget_ms: int = Field(alias="latencyBudgetMs", gt=0)
    fail_mode: Literal["closed", "open"] | None = Field(None, alias="failMode")
    standards: dict[str, StandardRef]
    modes: list[Literal["cli", "rest", "mcp", "a2a"]]
    engines: Engines
    io: dict[str, Any] = {}
    resources: dict[str, str] = {}
    dependencies: list[str] = []
    tests: Tests
    config: dict[str, ConfigParam] = {}

    @field_validator("standards")
    @classmethod
    def _standards(cls, v: dict) -> dict:
        if not v:
            raise ValueError("standards 매핑이 비어 있다 (DP7)")
        return v

    @field_validator("dependencies")
    @classmethod
    def _standalone(cls, v: list) -> list:
        if v:
            raise ValueError("dependencies 는 비어 있어야 한다 (DP2 홀로 서기)")
        return v

    @model_validator(mode="after")
    def _fail_default(self):
        if self.fail_mode is None:
            self.fail_mode = SERIES_FAIL_DEFAULT[self.series]
        return self


class Manifest(_M):
    api_version: Literal["aegismesh/v1"] = Field(alias="apiVersion")
    kind: Literal["Agent"]
    metadata: Metadata
    spec: Spec
    policy: dict[str, Any] = {}

    @property
    def id(self) -> str:
        return self.metadata.id

    @property
    def item_id(self) -> str:
        """도식 항목 ID (대문자, 예 D1-05 / X05)."""
        return self.metadata.id.upper()


def load_manifest(path: str | Path) -> Manifest:
    return Manifest.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
