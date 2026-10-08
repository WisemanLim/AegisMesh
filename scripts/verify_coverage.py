#!/usr/bin/env python3
"""verify_coverage.py — 도식 항목 대비 산출물 누락 검사 (CI 필수 단계, DP10·FR-P16).

사용: python scripts/verify_coverage.py [--stage N] [--json]
엄격 범위(stage ≤ N 이고 P0) 항목이 하나라도 누락이면 exit 1.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aegis.coverage import report  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", type=int, default=None, help="엄격 검사 로드맵 단계 (기본 AEGIS_COVERAGE_STAGE 또는 5)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = report(a.stage)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        for it in r["items"]:
            mark = "OK " if it["implemented"] else ("ERR" if it["strict"] else "-- ")
            if it["errors"] and (it["strict"] or it["agent"]):
                print(f"[{mark}] {it['id']:<7} {it['priority']} s{it['stage']} {'; '.join(it['errors'])}")
        s = r["strict"]
        print(f"coverage: 전체 {r['implemented']}/{r['total']} · 엄격 {s['implemented']}/{s['total']}")
    return 1 if r["strict"]["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
