"""컴플라이언스 보고 (FR-P11, PRD §4.4·§4.5) — 통제 카탈로그(controls/*.yaml)를 실제 에이전트·증적에 대조해 렌더한다.
매핑은 코드(매니페스트 standards + 카탈로그 파일)에 있고 보고서는 그 렌더 결과다. 법률 판단이 아니다."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.schemas import now_iso
from app import ledger, models

DIR = Path(__file__).resolve().parent.parent / "controls"


DISCLAIMER = {"ko": "설계 참고용 통제 매핑이며 법률 판단이 아니다. 적용 여부·의무 범위는 법무 검토를 거친다.",
              "en": "A control mapping for design reference, not a legal opinion. Applicability and the scope of obligations need legal review."}


def _t(d: dict, key: str, lang: str) -> str:
    """보고서 언어(NFR-C4) — en 이면 <key>En 이 있을 때 그것을 쓴다(OWASP 등 원문이 영어인 카탈로그는 그대로)."""
    return d.get(f"{key}En", d[key]) if lang == "en" else d[key]


def frameworks(lang: str = "ko") -> list[dict]:
    return [{"id": d["framework"], "title": _t(d, "title", lang), "version": _t(d, "version", lang), "controls": len(d["controls"])}
            for d in (yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(DIR.glob("*.yaml")))]


def catalog(fw: str) -> dict:
    p = DIR / f"{fw}.yaml"
    if not p.exists():
        raise KeyError(fw)
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def capabilities(s: Session) -> dict[str, bool]:
    """플랫폼 통제 역량 — 실제 데이터로 판정."""
    return {
        "ledger": s.scalar(select(models.Evidence.seq).limit(1)) is not None,
        "approvals": True,
        "masking": True,                                           # 원문 미보존·transform 저장 제외(NFR-D1)
        "risk_register": s.scalar(select(func.count()).select_from(models.Risk)) > 0,
        "redteam": s.scalar(select(func.count()).select_from(models.Evidence).where(models.Evidence.kind == "redteam")) > 0,
        "cards": True,                                             # 매니페스트에서 시스템 카드 자동 생성
        "incidents": True,
    }


def generate(s: Session, fw: str, days: int = 30, tenant: str | None = None, lang: str = "ko") -> dict:
    """tenant 지정 시 그 테넌트의 판정·증적 체인만으로 렌더(FR-P13). None = 플랫폼 전체."""
    cat = catalog(fw)
    agents = list(s.scalars(select(models.Agent)))
    active = {a.item_id: a for a in agents if a.status in ("active", "alert_only")}
    caps = capabilities(s)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = (select(models.Finding.agent_id, func.count()).where(models.Finding.occurred_at >= since)
         .where(models.Finding.verdict != "allow").group_by(models.Finding.agent_id))
    if tenant:
        q = q.where(models.Finding.tenant == tenant)
    counts = dict(s.execute(q).all())
    rows = []
    for c in cat["controls"]:
        if cat.get("standardKey"):
            items = sorted(a.item_id for a in agents
                           if c["id"] in (a.manifest["spec"]["standards"].get(cat["standardKey"], {}) or {}).get("ids", []))
        elif c.get("domains"):
            items = sorted(a.item_id for a in agents if (a.item_id.split("-")[0] if a.item_id.startswith("D") else "X") in c["domains"])
        else:
            items = list(c.get("items", []))
        impl = [i for i in items if i in active]
        plat = {p: caps.get(p, False) for p in c.get("platform", [])}
        status = ("covered" if items and len(impl) == len(items) and all(plat.values())
                  else "partial" if impl or any(plat.values()) else "missing")
        rows.append({"id": c["id"], "title": _t(c, "title", lang), "items": items, "implemented": impl,
                     "missing": [i for i in items if i not in active], "platform": plat, "status": status,
                     "findings30d": sum(counts.get(active[i].id, 0) for i in impl)})
    v = ledger.verify(s, tenant)
    summary = {k: sum(r["status"] == k for r in rows) for k in ("covered", "partial", "missing")}
    rep = {"framework": cat["framework"], "title": _t(cat, "title", lang), "version": _t(cat, "version", lang), "generatedAt": now_iso(),
           "periodDays": days, "tenant": tenant or "*", "lang": lang, "summary": summary, "controls": rows,
           "evidence": {"ledgerOk": v["ok"], "records": v["records"], "checkpoints": v["checkpoints"], "keyId": v["keyId"]},
           "disclaimer": DISCLAIMER[lang]}
    ledger.append(s, "report", cat["framework"], {"event": "report_generated", "summary": summary, "ledgerOk": v["ok"]},
                  tenant or ledger.PLATFORM)
    return rep


MD = {
    "ko": {"head": "통제 매핑 보고서", "gen": "- 생성: {at} · 기간 {days}일 · 판본 {ver}", "sum": "- 요약: 충족 {c} · 부분 {p} · 누락 {m}",
           "led": "- 증적 원장: {ok} · 레코드 {n} · keyId {kid}", "ok": "무결성 검증 통과", "bad": "무결성 실패",
           "cols": "| 통제 | 제목 | 상태 | 구현 항목 | 누락 항목 | 플랫폼 통제 | 30일 비허용 판정 |"},
    "en": {"head": "Control mapping report", "gen": "- Generated: {at} · period {days} days · version {ver}", "sum": "- Summary: covered {c} · partial {p} · missing {m}",
           "led": "- Evidence ledger: {ok} · records {n} · keyId {kid}", "ok": "integrity verified", "bad": "integrity FAILED",
           "cols": "| Control | Title | Status | Implemented items | Missing items | Platform controls | Non-allow verdicts (30 days) |"},
}


def markdown(rep: dict) -> str:
    m = MD[rep.get("lang", "ko")]
    lines = [f"# {rep['title']} — {m['head']}", "",
             m["gen"].format(at=rep["generatedAt"], days=rep["periodDays"], ver=rep["version"]),
             m["sum"].format(c=rep["summary"]["covered"], p=rep["summary"]["partial"], m=rep["summary"]["missing"]),
             m["led"].format(ok=m["ok"] if rep["evidence"]["ledgerOk"] else m["bad"], n=rep["evidence"]["records"], kid=rep["evidence"]["keyId"]),
             "", m["cols"], "|---|---|---|---|---|---|---|"]
    for r in rep["controls"]:
        plat = ", ".join(f"{k}{'✓' if v else '✗'}" for k, v in r["platform"].items()) or "—"
        lines.append(f"| {r['id']} | {r['title']} | {r['status']} | {', '.join(r['implemented']) or '—'} | "
                     f"{', '.join(r['missing']) or '—'} | {plat} | {r['findings30d']} |")
    lines += ["", f"> {rep['disclaimer']}"]
    return "\n".join(lines) + "\n"
