"""탐지 엔진 플러그인 인터페이스 (DP8 — 탐지기는 교체 가능).

엔진은 판정하지 않는다. 신호(Signal)만 낸다. 판정은 에이전트 core 의 몫이다.
엔진 모듈 = `agents/<id>/engines/<engine_id>.py` 에 `scan(req) -> list[Signal]` 함수 하나.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from aegis.schemas import EvidenceItem, JudgeRequest, Severity


class Signal(BaseModel):
    rule: str                                   # 에이전트 내부 규칙 이름 (ruleId 접미사)
    score: float = Field(ge=0.0, le=1.0)        # 신뢰도
    severity: Severity = "medium"
    evidence: EvidenceItem


class Engine(Protocol):
    id: str

    def scan(self, req: JudgeRequest) -> list[Signal]: ...


def walk_strings(obj, path: str = "args"):
    """중첩 dict·list 안의 문자열 값을 (경로, 값) 으로 순회 — 도구 인자 검사용."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}[{i}]")


def signal(rule: str, score: float, severity: Severity, location: str, note: str, kind: str = "check",
           offset: int | None = None, length: int | None = None) -> Signal:
    """엔진 공통 신호 생성 — 근거(evidence) 를 반드시 동반한다(DP3)."""
    return Signal(rule=rule, score=score, severity=severity,
                  evidence=EvidenceItem(kind=kind, location=location, note=note, offset=offset, length=length))


def artifact_of(req: JudgeRequest, *kinds: str) -> dict | None:
    """상시 점검 대상 중 이 엔진이 다루는 종류만 꺼낸다."""
    a = req.artifact or {}
    return a if a.get("kind") in kinds else None


def sibling(file: str, name: str):
    """같은 engines/ 폴더의 다른 엔진 모듈 — 이중 판정 엔진이 규칙 엔진을 그대로 재사용한다(코드 복제 없음)."""
    path = Path(file).with_name(f"{name}.py")
    key = f"aegis_sibling.{path.parent.parent.name.replace('-', '_')}.{name}"
    if key not in sys.modules:
        spec = importlib.util.spec_from_file_location(key, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[key] = mod
        spec.loader.exec_module(mod)
    return sys.modules[key]
