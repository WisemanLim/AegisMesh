#!/usr/bin/env python3
"""new_agent.py — 도식 항목에서 에이전트 골격(agent.yaml·디렉터리) 생성. core·engine·시험 데이터는 작성자가 채운다.

사용: python scripts/new_agent.py D1-05 hidden-payloads --gate input --engine unicode_rules \
        --verdicts block,transform,allow [--cwe CWE-94] [--llm LLM01] [--asi ASI01]
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("item"); ap.add_argument("slug")
    ap.add_argument("--gate", required=True, choices=["input", "tool", "output", "evidence", "offline"])
    ap.add_argument("--engine", required=True)
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--series"); ap.add_argument("--budget", type=int, default=30)
    ap.add_argument("--llm"); ap.add_argument("--asi"); ap.add_argument("--atlas"); ap.add_argument("--cwe")
    ap.add_argument("--name", help="영문 이름 (기본: 도식 원문 + Detector)")
    a = ap.parse_args()

    d = json.loads((ROOT / "diagram_items.json").read_text(encoding="utf-8"))
    it = next((x for x in [*d["items"], *d["gaps"]] if x["id"] == a.item.upper()), None)
    if not it:
        print(f"도식에 없는 항목: {a.item}", file=sys.stderr)
        return 1
    dom = next((x for x in d["domains"] if x["id"] == it.get("domain")), None)
    std_base = (dom or it)["standards"]

    def ids(arg, key):
        return arg.split(",") if arg else std_base.get(key, {}).get("ids", [])

    standards = {
        "owasp-llm": {"version": "2026", "ids": ids(a.llm, "owasp-llm")},
        "owasp-asi": {"version": "2026", "ids": ids(a.asi, "owasp-asi")},
        "mitre-atlas": {"version": "2026.06", "ids": ids(a.atlas, "mitre-atlas")},
        "cwe": {"version": "4.20", "ids": a.cwe.split(",") if a.cwe else []},
    }
    standards = {k: v for k, v in standards.items() if v["ids"]}
    aid = it["id"].lower()
    m = {
        "apiVersion": "aegismesh/v1", "kind": "Agent",
        "metadata": {"id": aid, "name": a.name or f"{it['nameEn']} Detector", "nameKo": f"{it['nameKo']} 탐지기",
                     "version": "1.0.0",
                     "source": {"diagram": "Security Risks in AI Agents" if "domain" in it else "AegisMesh gap analysis",
                                "domain": it.get("domain", "X"), "item": it["nameEn"]}},
        "spec": {"series": a.series or it["series"], "gate": a.gate, "isolation": "L0",
                 "verdicts": a.verdicts.split(","), "latencyBudgetMs": a.budget, "standards": standards,
                 "modes": ["cli", "rest", "mcp"],
                 "engines": {"default": a.engine, "available": [{"id": a.engine, "kind": "builtin"}]},
                 "io": {"input": {"schema": "aegismesh.io/JudgeRequest/v1"}, "output": {"schema": "aegismesh.io/Finding/v1"}},
                 "resources": {"cpu": "100m", "memory": "128Mi"}, "dependencies": [],
                 "tests": {"golden": "tests/golden", "attacks": "tests/attacks", "baseline": "tests/baseline.json",
                           "thresholds": {"falsePositiveRate": 0.005, "falseNegativeRate": 0.10}}},
    }
    path = ROOT / "agents" / f"{aid}-{a.slug}"
    for sub in ("engines", "tests/golden", "tests/attacks"):
        (path / sub).mkdir(parents=True, exist_ok=True)
    (path / "agent.yaml").write_text(yaml.safe_dump(m, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
