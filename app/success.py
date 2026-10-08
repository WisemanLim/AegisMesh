"""성공 지표 (원본 PRD §15.1 · PRD.md §5) — 커버리지·품질·성능·도입·운영 KPI 12종을 실데이터로 계산해 1단계·정상 운영 목표와 비교한다.

값이 없으면 '측정 전'으로 둔다(추정하지 않는다). 원장 무결성은 무거운 전체 검증이라 일 1회 스냅샷(원장 `kpi`)에서 읽는다.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger, models
from app.format_utils import iso_to_epoch

ROOT = Path(__file__).resolve().parent.parent
LOWER, HIGHER = "lower", "higher"
# id, 묶음, 이름(ko, en), 단위, 방향, 1단계 목표, 정상 운영 목표, 측정 방법(ko, en)
SPEC = [
    ("coverage", "coverage", ("도식 80항목 구현률", "Diagram coverage (80 items)"), "%", HIGHER, None, 100.0,
     ("verify_coverage — 1단계는 P0 39건", "verify_coverage — stage 1 = 39 P0 items")),
    ("owasp-llm", "coverage", ("OWASP LLM 2026 대응", "OWASP LLM 2026 coverage"), "/10", HIGHER, 9, 10,
     ("매니페스트 standards 집계", "manifest standards")),
    ("owasp-asi", "coverage", ("OWASP ASI 2026 대응", "OWASP ASI 2026 coverage"), "/10", HIGHER, 6, 10,
     ("매니페스트 standards 집계", "manifest standards")),
    ("fp-rate", "quality", ("인라인 오탐률", "Inline false-positive rate"), "%", LOWER, 1.0, 0.5,
     ("주간 골든셋 재생", "weekly golden-set replay")),
    ("miss-rate", "quality", ("공격 코퍼스 미탐률", "Attack-corpus miss rate"), "%", LOWER, 20.0, 10.0,
     ("코퍼스 정기 실행(최근)", "latest corpus run")),
    ("p95-input", "performance", ("입력 관문 p95", "Input gate p95"), "ms", LOWER, 150.0, 80.0, ("관문 계측 24시간", "gate records, 24 h")),
    ("p95-tool", "performance", ("도구 관문 p95", "Tool gate p95"), "ms", LOWER, 40.0, 20.0, ("관문 계측 24시간", "gate records, 24 h")),
    ("first-verdict", "adoption", ("첫 판정까지 시간", "Time to first verdict"), "min", LOWER, 120.0, 30.0,
     ("설치(부트스트랩) → 첫 관문 판정", "install (bootstrap) → first gate verdict")),
    ("block-conversion", "adoption", ("차단 모드 전환 비율", "Blocking-mode conversion"), "%", HIGHER, 30.0, 70.0,
     ("적용 중 테넌트 중 부분·전체 차단 비율", "share of applied tenants on partial/full blocking")),
    ("explained", "operations", ("판정 설명 제공률", "Verdict explanation rate"), "%", HIGHER, 100.0, 100.0,
     ("7일 판정의 rule_id·근거·신뢰도", "rule_id · evidence · confidence on 7-day findings")),
    ("integrity", "operations", ("증적 무결성 검증 성공률", "Ledger integrity verification"), "%", HIGHER, 100.0, 100.0,
     ("일 1회 체인·체크포인트 검증(최근 30회)", "daily chain + checkpoint verification (last 30)")),
    ("reconstruct", "operations", ("사건 평균 재구성 시간", "Mean incident reconstruction time"), "min", LOWER, 60.0, 10.0,
     ("사건 생성 → 재현 전부 일치", "incident opened → replay fully matched")),
]


def _since(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _p95(xs: list[float]) -> float | None:
    xs = sorted(xs)
    return round(xs[max(0, int(len(xs) * 0.95) - 1)], 2) if xs else None


def _status(v, target, way) -> str | None:
    if v is None or target is None:
        return None
    return "met" if (v <= target if way == LOWER else v >= target) else "missed"


def _coverage(s: Session) -> tuple[dict, dict, dict]:
    diagram = json.loads((ROOT / "diagram_items.json").read_text())
    active = list(s.scalars(select(models.Agent).where(models.Agent.status.in_(("active", "alert_only")))))
    have = {a.item_id for a in active}
    items = [i["id"] for i in diagram["items"]] + [g["id"] for g in diagram["gaps"]]
    p0 = [i["id"] for i in diagram["items"] if i.get("priority") == "P0"]
    llm, asi = set(), set()
    for a in active:
        st = (a.manifest.get("spec") or {}).get("standards") or {}
        llm |= set((st.get("owasp-llm") or {}).get("ids") or [])
        asi |= set((st.get("owasp-asi") or {}).get("ids") or [])
    done, p0done = sum(i in have for i in items), sum(i in have for i in p0)
    cov = {"value": round(done / len(items) * 100, 1), "display": f"{done}/{len(items)}",
           "detail": {"p0": f"{p0done}/{len(p0)}", "p0Met": p0done == len(p0)}}
    llm10 = sorted(x for x in llm if x in {f"LLM{n:02d}" for n in range(1, 11)})
    asi10 = sorted(x for x in asi if x in {f"ASI{n:02d}" for n in range(1, 11)})
    return cov, {"value": len(llm10), "display": f"{len(llm10)}/10", "detail": {"ids": llm10}}, \
        {"value": len(asi10), "display": f"{len(asi10)}/10", "detail": {"ids": asi10}}


def _quality(s: Session) -> tuple[dict, dict]:
    def latest(ref_like):
        return s.scalars(select(models.Evidence).where(models.Evidence.kind == "quality", models.Evidence.ref_id.like(ref_like))
                         .order_by(models.Evidence.seq.desc()).limit(1)).first()
    from app import quality
    g, c = latest("golden"), quality.corpus_headline(s, variant="deep") or quality.corpus_headline(s)   # 깊은 검사 실측이 있으면 그 값(탐지 기준)
    fp = {"value": round(g.body["overallFpRate"] * 100, 3), "display": f"{g.body['overallFpRate'] * 100:.2f}%",
          "detail": {"samples": g.body.get("samples"), "synthetic": g.body.get("synthetic"), "at": g.created_at}} if g else {"value": None}
    miss = {"value": round(c["missRate"] * 100, 2), "display": f"{c['missRate'] * 100:.1f}%",
            "detail": {"variant": c["variant"], "corpus": " · ".join(x["name"] for x in c["corpora"]), "source": " · ".join(x["source"] for x in c["corpora"]),
                       "n": c["items"], "at": c["at"]}} if c else {"value": None}
    return fp, miss


def _gates(s: Session, tenant: str | None) -> tuple[dict, dict]:
    q = select(models.Evidence.body).where(models.Evidence.kind == "gate", models.Evidence.created_at >= _since(24))
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    by: dict[str, list[float]] = {}
    for b in s.scalars(q.order_by(models.Evidence.seq.desc()).limit(50000)):
        if b.get("latencyMs") is not None:
            by.setdefault(b.get("gate"), []).append(float(b["latencyMs"]))
    out = []
    for g in ("input", "tool"):
        v = _p95(by.get(g, []))
        out.append({"value": v, "display": f"{v} ms" if v is not None else None, "detail": {"records": len(by.get(g, []))}})
    return out[0], out[1]


def _first_verdict(s: Session) -> dict:
    from app import console
    st = console.setup_status(s)
    v = st.get("minutesToFirstVerdict")
    return {"value": v, "display": f"{v} min" if v is not None else None,
            "detail": {"installedAt": st.get("installedAt"), "firstVerdictAt": st.get("firstVerdictAt")}}


def _conversion(s: Session, tenant: str | None) -> dict:
    q = select(models.ProfileApplication).where(models.ProfileApplication.active.is_(True))
    if tenant:
        q = q.where(models.ProfileApplication.tenant == tenant)
    by: dict[str, set] = {}
    for a in s.scalars(q):
        by.setdefault(a.tenant, set()).add(a.stage)
    if not by:
        return {"value": None, "detail": {"tenants": 0}}
    conv = sorted(t for t, st in by.items() if st & {"partial", "enforce"})
    return {"value": round(len(conv) / len(by) * 100, 1), "display": f"{len(conv)}/{len(by)}",
            "detail": {"tenants": len(by), "converted": conv, "observeOnly": sorted(set(by) - set(conv))}}


def _explained(s: Session, tenant: str | None) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=7)
    q = select(models.Finding.valid, models.Finding.rule_id, models.Finding.confidence, models.Finding.body).where(models.Finding.occurred_at >= since)
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    n = ok = 0
    for valid, rule, conf, body in s.execute(q.limit(20000)):
        n += 1
        ok += bool(valid and rule and conf is not None and (body or {}).get("evidence"))
    return {"value": round(ok / n * 100, 2), "display": f"{ok}/{n}", "detail": {"findings": n}} if n else {"value": None, "detail": {"findings": 0}}


def _integrity(s: Session, current: dict | None = None) -> dict:
    snaps = list(s.scalars(select(models.Evidence).where(models.Evidence.kind == "kpi").order_by(models.Evidence.seq.desc()).limit(30)))
    integ = [current] if current else []
    integ += [r.body.get("integrity") or {} for r in snaps][: 30 - len(integ)]
    runs = [c for i in integ for c in i.get("chains", [])]
    if not runs:
        return {"value": None, "detail": {"runs": 0}}
    ok = sum(bool(c.get("ok")) for c in runs)
    return {"value": round(ok / len(runs) * 100, 2), "display": f"{ok}/{len(runs)}",
            "detail": {"runs": len(runs), "lastRecords": integ[0].get("records"), "lastAt": None if current else snaps[0].created_at}}


def _reconstruct(s: Session, tenant: str | None) -> dict:
    q = select(models.Evidence).where(models.Evidence.kind == "replay").order_by(models.Evidence.seq.desc()).limit(500)
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    first: dict[str, models.Evidence] = {}
    for r in s.scalars(q):
        if r.body.get("total") and r.body.get("matched") == r.body.get("total"):
            first[r.ref_id] = r                                       # 내림차순이라 마지막 대입 = 가장 이른 완전 일치
    mins = []
    for iid, r in first.items():
        inc = s.get(models.Incident, iid)
        if inc is not None:
            opened = inc.created_at if inc.created_at.tzinfo else inc.created_at.replace(tzinfo=timezone.utc)
            mins.append((iso_to_epoch(r.created_at) - opened.timestamp()) / 60)
    if not mins:
        return {"value": None, "detail": {"incidents": 0}}
    v = round(sum(mins) / len(mins), 1)
    return {"value": v, "display": f"{v} min", "detail": {"incidents": len(mins)}}


def compute(s: Session, tenant: str | None = None, integrity: dict | None = None) -> dict:
    cov, llm, asi = _coverage(s)
    fp, miss = _quality(s)
    pin, ptool = _gates(s, tenant)
    vals = {"coverage": cov, "owasp-llm": llm, "owasp-asi": asi, "fp-rate": fp, "miss-rate": miss, "p95-input": pin, "p95-tool": ptool,
            "first-verdict": _first_verdict(s), "block-conversion": _conversion(s, tenant), "explained": _explained(s, tenant),
            "integrity": _integrity(s, integrity), "reconstruct": _reconstruct(s, tenant)}
    items = []
    for kid, group, (ko, en), unit, way, t1, t, (mko, men) in SPEC:
        v = vals[kid]
        s1 = (("met" if v["detail"]["p0Met"] else "missed") if kid == "coverage" and v.get("value") is not None else _status(v.get("value"), t1, way))
        items.append({"id": kid, "group": group, "nameKo": ko, "nameEn": en, "unit": unit, "direction": way, "value": v.get("value"),
                      "display": v.get("display"), "detail": v.get("detail", {}), "stage1Target": t1 if kid != "coverage" else "P0 39/39",
                      "target": t, "stage1": s1, "status": _status(v.get("value"), t, way), "methodKo": mko, "methodEn": men})
    measured = [i for i in items if i["value"] is not None]
    trend = {}
    for r in reversed(list(s.scalars(select(models.Evidence).where(models.Evidence.kind == "kpi").order_by(models.Evidence.seq.desc()).limit(30)))):
        for it in r.body.get("items", []):
            trend.setdefault(it["id"], []).append({"at": r.created_at, "value": it.get("value")})
    return {"generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tenant": tenant, "items": items, "trend": trend,
            "summary": {"total": len(items), "measured": len(measured), "stage1Met": sum(i["stage1"] == "met" for i in measured),
                        "targetMet": sum(i["status"] == "met" for i in measured)}, "keyMetric": "block-conversion"}


def snapshot(s: Session, by: str) -> dict:
    """일 1회 기록 — 전체 원장 검증(체인·체크포인트)을 돌려 무결성 지표의 근거로 남긴다. 원장 레코드는 한 번만 쓴다(수정 불가)."""
    v = ledger.verify(s)
    integ = {"ok": v["ok"], "records": v["records"], "chains": [{"chain": c["chain"], "ok": c["ok"], "records": c["records"]} for c in v["chains"]]}
    out = compute(s, integrity=integ)
    rec = ledger.append(s, "kpi", "success", {"event": "kpi_snapshot", "integrity": integ, "by": by,
                                              "items": [{"id": i["id"], "value": i["value"], "stage1": i["stage1"], "status": i["status"]}
                                                        for i in out["items"]]})
    return {"seq": rec.seq, "integrity": integ, "summary": out["summary"]}
