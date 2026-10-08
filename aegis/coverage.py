"""누락 검증 (DP10, FR-P16) — 도식 80 항목 대비 매니페스트·요구사항·시험·표준 매핑 검사.

엄격 범위(strict): 로드맵 stage ≤ AEGIS_COVERAGE_STAGE 이고 P0 인 항목 → 누락 시 실패.
나머지 항목은 누락을 보고만 한다(단계적 도입, PRD §15.1 "1단계 P0 100%").
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from aegis.agent import ROOT, agents_dir
from aegis.manifest import load_manifest


ITEM_DIR_RE = re.compile(r"^(d(?:10|[1-9])-0[1-7]|x(?:0[1-9]|10))(?:-|$)")


def diagram_path() -> Path:
    return Path(os.environ.get("AEGIS_DIAGRAM", ROOT / "diagram_items.json"))


def load_diagram() -> dict:
    return json.loads(diagram_path().read_text(encoding="utf-8"))


def all_items(diagram: dict | None = None) -> list[dict]:
    d = diagram or load_diagram()
    return [*d["items"], *d["gaps"]]


@dataclass
class ItemStatus:
    id: str
    priority: str
    stage: int
    strict: bool
    agent: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def implemented(self) -> bool:
        return self.agent is not None and not self.errors


def _nonempty(p: Path) -> bool:
    if p.is_dir():
        return any(f.stat().st_size > 0 for f in p.glob("*.jsonl"))
    return p.is_file() and p.stat().st_size > 0


def check(stage: int | None = None) -> list[ItemStatus]:
    stage = int(os.environ.get("AEGIS_COVERAGE_STAGE", "5")) if stage is None else stage
    diagram = load_diagram()
    manifests, broken = {}, {}
    for path in sorted(agents_dir().glob("*/agent.yaml")):
        try:
            m = load_manifest(path)
            manifests[m.item_id] = (path.parent, m)
        except (ValidationError, ValueError) as exc:
            if mt := ITEM_DIR_RE.match(path.parent.name):
                broken[mt.group(1).upper()] = str(exc).splitlines()[0]
    out = []
    for it in all_items(diagram):
        st = ItemStatus(id=it["id"], priority=it["priority"], stage=it["stage"],
                        strict=it["stage"] <= stage and it["priority"] == "P0")
        if not it.get("fr"):
            st.errors.append("요구사항(FR) 없음")
        if it["id"] in broken:
            st.errors.append(f"매니페스트 스키마 오류: {broken[it['id']]}")
        elif it["id"] not in manifests:
            st.errors.append("에이전트 매니페스트 없음")
        else:
            path, m = manifests[it["id"]]
            st.agent = m.id
            if it["id"].startswith("D") and (m.metadata.source.domain != it["domain"]
                                            or m.metadata.source.item != it["nameEn"]):
                st.errors.append(f"도식 추적 불일치: {m.metadata.source.domain}/{m.metadata.source.item}")
            if not any(s.ids for s in m.spec.standards.values()):
                st.errors.append("표준 매핑 없음")
            for f in ("golden", "attacks", "baseline"):
                if not _nonempty(path / getattr(m.spec.tests, f)):
                    st.errors.append(f"시험 자산 없음: {f}")
            if not (path / "core.py").is_file():
                st.errors.append("core.py 없음")
        out.append(st)
    return out


def report(stage: int | None = None) -> dict:
    items = check(stage)
    strict = [i for i in items if i.strict]
    return {
        "total": len(items),
        "implemented": sum(i.implemented for i in items),
        "strict": {"total": len(strict), "implemented": sum(i.implemented for i in strict),
                   "failures": [{"id": i.id, "errors": i.errors} for i in strict if not i.implemented]},
        "items": [{"id": i.id, "priority": i.priority, "stage": i.stage, "strict": i.strict,
                   "agent": i.agent, "implemented": i.implemented, "errors": i.errors} for i in items],
    }
