#!/usr/bin/env python3
"""OpenAPI 계약 스냅샷 (COMPLIANCE 추가 시험 'OpenAPI 계약 적합성') — 공개 계약의 깨지는 변경을 시험이 잡도록 현재 계약을 기록한다.

기록 = 경로·메서드별 매개변수(위치·필수)·요청 본문 필수 필드·응답 코드. 계약을 의도적으로 바꿨으면 `make contract-update`.
"""
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "test" / "contract" / "openapi.snapshot.json"


def _schema(doc: dict, ref: dict) -> dict:
    while ref and "$ref" in ref:
        name = ref["$ref"].split("/")[-1]
        ref = doc["components"]["schemas"].get(name, {})
    return ref or {}


def contract(doc: dict) -> dict:
    ops = {}
    for path, item in doc["paths"].items():
        for method, op in item.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            body = (op.get("requestBody") or {}).get("content", {}).get("application/json", {}).get("schema")
            sch = _schema(doc, body or {})
            ops[f"{method.upper()} {path}"] = {
                "params": sorted(f"{p['in']}:{p['name']}{'!' if p.get('required') else ''}" for p in op.get("parameters", [])),
                "bodyRequired": bool((op.get("requestBody") or {}).get("required")),
                "bodyFields": sorted(f"{k}{'!' if k in sch.get('required', []) else ''}" for k in (sch.get("properties") or {})),
                "responses": sorted(op.get("responses", {})),
                "tags": op.get("tags", []),
            }
    return {"openapi": doc.get("openapi"), "operations": dict(sorted(ops.items()))}


def current() -> dict:
    from app.main import app
    return contract(app.openapi())


if __name__ == "__main__":
    c = current()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(c, ensure_ascii=False, indent=1) + "\n")
    print(f"contract snapshot: {len(c['operations'])} operations → {OUT}", file=sys.stderr)
