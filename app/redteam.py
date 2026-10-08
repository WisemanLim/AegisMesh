"""상시 레드팀 (FR-P10, X09) — 내부 공격 코퍼스(에이전트별 tests/attacks)를 재생해 회귀 기준선과 비교한다.
대상은 플랫폼 자신의 에이전트뿐이다(외부 자산 미대상 — 이중 용도 통제 §13.1). 언어별(ko/en) 성능 분해는 D10-05 공정성 지표로 쓴다."""
from __future__ import annotations

import json
import re
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.harness import _lines
from aegis.schemas import JudgeRequest
from app import ledger, models, registry

HANGUL = re.compile(r"[가-힣]")


def _group(raw: dict) -> str:
    return "ko" if HANGUL.search(json.dumps(raw.get("request", {}), ensure_ascii=False)) else "en"


def run_campaign(s: Session, by: str, agent_ids: list[str] | None = None) -> dict:
    rows = s.scalars(select(models.Agent).where(models.Agent.origin == "builtin",
                                                models.Agent.status.in_(("active", "alert_only")))).all()
    ids = agent_ids or sorted(a.id for a in rows)
    t0 = time.perf_counter()
    results, groups = [], {}
    for aid in ids:
        ag = registry.runtime_agent(aid)
        t = ag.manifest.spec.tests
        base = json.loads((ag.path / t.baseline).read_text()) if (ag.path / t.baseline).exists() else {}
        tp = fn = fp = tn = 0
        for kind, d in (("golden", ag.path / t.golden), ("attacks", ag.path / t.attacks)):
            for _label, raw in _lines(d):
                f = ag.judge(JudgeRequest.model_validate(raw["request"]))
                g = groups.setdefault(_group(raw), {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
                hit = f.verdict != "allow"
                key = ("tp" if hit else "fn") if kind == "attacks" else ("fp" if hit else "tn")
                g[key] += 1
                tp, fn, fp, tn = tp + (key == "tp"), fn + (key == "fn"), fp + (key == "fp"), tn + (key == "tn")
        det = tp / (tp + fn) if tp + fn else 1.0
        results.append({"agent": aid, "detectionRate": round(det, 4), "baseline": base.get("detectionRate", 0.0),
                        "fpRate": round(fp / (fp + tn), 4) if fp + tn else 0.0})
    fairness = [{"group": k, "n": sum(v.values()),
                 "tpr": round(v["tp"] / (v["tp"] + v["fn"]), 4) if v["tp"] + v["fn"] else None,
                 "fpr": round(v["fp"] / (v["fp"] + v["tn"]), 4) if v["fp"] + v["tn"] else None} for k, v in sorted(groups.items())]
    regressions = [r for r in results if r["detectionRate"] < r["baseline"]]
    summary = {"event": "campaign", "by": by, "target": "internal-corpus", "agents": len(results),
               "regressions": regressions, "fairness": fairness, "results": results,
               "durationMs": round((time.perf_counter() - t0) * 1000, 1)}
    rec = ledger.append(s, "redteam", f"campaign:{len(results)}", summary)
    from app import scanner                                  # X09 회귀 게이트 판정 → 판정·사건 연계
    gate = scanner.run_scan(s, {"kind": "redteam_status", "name": "internal-corpus", "lastRunAgeSec": 0,
                                "results": results, "unregisteredTargets": []}, agent_ids=["x09"], by=by)
    return summary | {"seq": rec.seq, "verdict": gate["verdict"], "incidents": gate.get("incidents", [])}


def latest(s: Session) -> models.Evidence | None:
    return s.scalars(select(models.Evidence).where(models.Evidence.kind == "redteam")
                     .order_by(models.Evidence.seq.desc()).limit(1)).first()
