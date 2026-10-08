"""공정성·윤리 지표(SCR-N06, FR-D10-05) · 시스템·모델 카드(SCR-N07, FR-D10-06).

공정성 — 판정 기록의 요청 모양에 실린 가명 집단 라벨(subject.groups)·문자 체계(script)로 보호 대상별 차단율을 집계하고,
레드팀 코퍼스 캠페인의 집단별 오탐·미탐(라벨 있음)과 함께 d10-05 로 판정한다. 측정·추세는 원장 `fairness`, 한도 초과는 위험 등록부.
카드 — 보호 대상(시스템)·모델 점검 대상의 메타데이터(공급자·적용 프로파일·정책·데이터셋·평가·공정성)로 ko·en 카드를 만들고,
입력 지문이 바뀌면 '갱신 필요'(D10-06 stale-card · 배포 게이트 차단). 공개는 승인 후, 판은 덮어쓰지 않고 원장 `card` 에 쌓는다.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import approvals, ledger, models, policy, profiles, redteam, registry, scanner
from app.auth import utcnow
from app.format_utils import iso_to_epoch

REVIEW_DAYS = 180                       # 영향 평가 문서 재검토 주기
AUDIENCES = ("internal", "regulator", "external")
DATA_KINDS = ("dataset", "index_update")


class ComplianceError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _since(days: int) -> str:
    return (utcnow() - timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _targets(s: Session, tenant: str) -> list[models.ProtectedTarget]:
    return list(s.scalars(select(models.ProtectedTarget).where(models.ProtectedTarget.tenant == tenant).order_by(models.ProtectedTarget.created_at)))


def limits(s: Session, tenant: str) -> dict:
    """d10-05 한도 — 매니페스트 기본값 위에 테넌트 정책 agentParams."""
    base = {k: p.default for k, p in registry.runtime_agent("d10-05").manifest.spec.config.items()}
    pol = {k: v for k, v in (policy.spec_of(policy.latest(s, "default", tenant)).agent_params.get("d10-05") or {}).items() if k != "byPrincipal"}
    return base | pol


# ── 공정성 (SCR-N06) ─────────────────────────────────────────────
def block_rates(s: Session, tenant: str, target: str | None, days: int) -> tuple[list[dict], int]:
    """집단별 차단율 — 판정 기록의 가명 라벨(groups)과 문자 체계(lang 축 기본값). 원문·개인 식별 없음."""
    agg: dict[tuple[str, str], list[int]] = {}
    n = 0
    q = (select(models.Evidence).where(models.Evidence.kind == "gate", models.Evidence.tenant == tenant, models.Evidence.created_at >= _since(days))
         .order_by(models.Evidence.seq.desc()).limit(20000))
    for r in s.scalars(q):
        b = r.body
        if target and b.get("target") != target:
            continue
        sh = b.get("shape") or {}
        groups = dict(sh.get("groups") or {})
        if "lang" not in groups and sh.get("script"):
            groups["lang"] = sh["script"]
        if not groups:
            continue
        n += 1
        hit = b.get("verdict") == "block"
        for ax, g in groups.items():
            x = agg.setdefault((ax, str(g)), [0, 0])
            x[0] += 1
            x[1] += hit
    return [{"axis": ax, "group": g, "n": c, "blocks": k, "rate": round(k / c, 5)} for (ax, g), (c, k) in sorted(agg.items())], n


def gaps(rates: list[dict], min_n: int) -> dict:
    out = {}
    for ax in sorted({r["axis"] for r in rates}):
        gs = [r for r in rates if r["axis"] == ax and r["n"] >= min_n]
        if len(gs) >= 2:
            hi, lo = max(gs, key=lambda r: r["rate"]), min(gs, key=lambda r: r["rate"])
            out[ax] = {"gapPp": round((hi["rate"] - lo["rate"]) * 100, 3), "hi": hi["group"], "lo": lo["group"], "groups": len(gs)}
    return out


def perf_breakdown(s: Session) -> list[dict]:
    """레드팀 코퍼스(라벨 있음) 캠페인의 집단별 오탐·탐지 — 최저 오탐 집단 대비 격차(%p)."""
    rt = redteam.latest(s)
    rows = [dict(g) for g in ((rt.body.get("fairness") if rt else None) or []) if g.get("n")]
    fprs = [g["fpr"] for g in rows if g.get("fpr") is not None]
    best = min(fprs) if fprs else None
    for g in rows:
        g["missRate"] = round(1 - g["tpr"], 4) if g.get("tpr") is not None else None
        g["gapPp"] = round((g["fpr"] - best) * 100, 3) if g.get("fpr") is not None and best is not None else None
    return rows


def measure(s: Session, tenant: str, target: str | None, days: int, by: str) -> dict:
    lim = limits(s, tenant)
    rates, n = block_rates(s, tenant, target, days)
    perf = perf_breakdown(s)
    art = {"kind": "governance_snapshot", "name": f"fairness:{target or '*'}", "blockRates": rates,
           "fairness": [{k: g.get(k) for k in ("group", "n", "fpr", "tpr")} for g in perf]}
    r = scanner.run_scan(s, art, tenant, agent_ids=["d10-05"], by=by)
    g = gaps(rates, int(lim.get("minGroupSize", 30)))
    over = {ax: v for ax, v in g.items() if v["gapPp"] > float(lim.get("maxGapPp", 1.5))}
    risk = None
    if over:                                                     # 한도 초과 → 위험 등록부 자동 등록 (MSG-023) — 열린 같은 출처가 있으면 재사용
        src = f"fairness:{tenant}:{target or '*'}"
        risk = s.scalars(select(models.Risk).where(models.Risk.source == src, models.Risk.status == "open")).first()
        if risk is None:
            title = f"공정성 격차 한도 초과 — {target or tenant}: " + ", ".join(f"{ax} {v['gapPp']:.2f}%p ({v['hi']})" for ax, v in over.items())
            risk = models.Risk(id=f"R-{secrets.token_hex(3)}", title=title[:200], score=5.0, decision="open", source=src)
            s.add(risk)
            s.flush()
            ledger.append(s, "risk", risk.id, {"event": "registered", "by": by, "title": risk.title, "source": src, "decision": "open"})
    rec = ledger.append(s, "fairness", target or "*", {"event": "measured", "target": target, "days": days, "records": n, "blockRates": rates[:80],
                                                       "perf": perf[:20], "gaps": g, "over": over, "limits": lim, "verdict": r["verdict"],
                                                       "hits": [h["ruleId"] for h in r["hits"]], "traceId": r["traceId"],
                                                       "risk": risk.id if risk else None, "by": by}, tenant)
    return {"seq": rec.seq, "target": target, "records": n, "gaps": g, "over": over, "verdict": r["verdict"],
            "hits": [h["ruleId"] for h in r["hits"]], "traceId": r["traceId"], "risk": risk.id if risk else None}


def _hist(s: Session, tenant: str, kind: str, ref: str | None = None, limit: int = 200) -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.kind == kind, models.Evidence.tenant == tenant)
    if ref is not None:
        q = q.where(models.Evidence.ref_id == ref)
    return list(s.scalars(q.order_by(models.Evidence.seq.desc()).limit(limit)))


def assessments(s: Session, tenant: str) -> list[dict]:
    """영향 평가 문서 — 대상별 최근 평가·상태. 없음 = missing, 180일 경과·이후 공정성 한도 초과 = needs-update."""
    docs: dict[str, models.Evidence] = {}
    for r in _hist(s, tenant, "impact_assessment"):
        docs.setdefault(r.ref_id, r)
    over_at: dict[str, str] = {}
    for r in _hist(s, tenant, "fairness"):
        if r.body.get("over"):
            over_at.setdefault(r.ref_id, r.created_at)
    out = []
    for t in _targets(s, tenant):
        d = docs.get(t.name)
        if d is None:
            st = "missing"
        elif iso_to_epoch(d.created_at) < (utcnow() - timedelta(days=REVIEW_DAYS)).timestamp() or \
                (t.name in over_at and over_at[t.name] > d.created_at):
            st = "needs-update"
        else:
            st = d.body.get("status", "approved")
        out.append({"target": t.name, "status": st, "reviewedAt": d.created_at if d else None, "by": d.body.get("by") if d else None,
                    "summary": d.body.get("summary") if d else None, "fairnessAlertAt": over_at.get(t.name)})
    return out


def record_assessment(s: Session, tenant: str, target: str, summary: str, status: str, by: str) -> dict:
    if target not in {t.name for t in _targets(s, tenant)}:
        raise ComplianceError(404, f"보호 대상 {target} 없음")
    rec = ledger.append(s, "impact_assessment", target, {"event": "reviewed", "target": target, "summary": summary, "status": status, "by": by}, tenant)
    return {"seq": rec.seq, "target": target, "status": status}


def disclosure(s: Session, tenant: str) -> dict:
    r = next(iter(_hist(s, tenant, "disclosure", "fairness", 1)), None)
    return {"internal": r.body["internal"], "external": r.body["external"], "by": r.body.get("by"), "at": r.created_at} if r else \
        {"internal": True, "external": False, "by": None, "at": None}


def set_disclosure(s: Session, tenant: str, internal: bool, external: bool, by: str) -> dict:
    ledger.append(s, "disclosure", "fairness", {"event": "set", "internal": internal, "external": external, "by": by}, tenant)
    return disclosure(s, tenant)


def fairness_view(s: Session, tenant: str, target: str | None, days: int) -> dict:
    lim = limits(s, tenant)
    rates, n = block_rates(s, tenant, target, days)
    hist = [r for r in _hist(s, tenant, "fairness", limit=100) if target is None or r.ref_id == target][:12]
    latest = hist[0].body | {"at": hist[0].created_at, "seq": hist[0].seq} if hist else None
    trend = [{"at": r.created_at, "seq": r.seq, "verdict": r.body.get("verdict"),
              "maxGapPp": max((v["gapPp"] for v in (r.body.get("gaps") or {}).values()), default=0.0)} for r in reversed(hist)]
    asm = assessments(s, tenant)
    return {"target": target, "days": days, "limits": lim, "targets": [t.name for t in _targets(s, tenant)],
            "live": {"records": n, "blockRates": rates, "gaps": gaps(rates, int(lim.get("minGroupSize", 30)))},
            "latest": latest, "trend": trend, "perf": perf_breakdown(s), "assessments": asm,
            "assessmentFresh": sum(a["status"] == "approved" for a in asm), "disclosure": disclosure(s, tenant)}


# ── 시스템·모델 카드 (SCR-N07) ───────────────────────────────────
def _ctx(s: Session, tenant: str) -> dict:
    pol = policy.latest(s, "default", tenant)
    data = {t.name: str(t.artifact.get("version") or t.artifact.get("contentHash") or "—") for t in
            s.scalars(select(models.ScanTarget).where(models.ScanTarget.tenant == tenant, models.ScanTarget.kind.in_(DATA_KINDS)))}
    models_ = {t.name: t for t in s.scalars(select(models.ScanTarget).where(models.ScanTarget.tenant == tenant, models.ScanTarget.kind == "model"))}
    return {"policy": f"{pol.policy_id}@v{pol.version}" if pol else "builtin-default", "data": dict(sorted(data.items())), "models": models_}


def subjects(s: Session, tenant: str, ctx: dict) -> list[tuple[str, str, object]]:
    return [("system", t.name, t) for t in _targets(s, tenant)] + [("model", n, m) for n, m in sorted(ctx["models"].items())]


def _inputs(s: Session, tenant: str, kind: str, obj, ctx: dict) -> dict:
    """카드 지문 입력 — 바뀌면 카드 갱신 필요(모델·데이터셋·정책·적용 프로파일)."""
    if kind == "system":
        app_ = profiles.active_for(s, tenant, obj.name)
        return {"purpose": {"kind": obj.kind, "endpoint": obj.endpoint, "insertion": obj.insertion},
                "model": {"provider": obj.model_provider, "external": obj.external_model},
                "data": ctx["data"],
                "controls": {"profile": app_.profile_id if app_ else None, "stage": app_.stage if app_ else None,
                             "agents": len(app_.agent_ids) if app_ else 0, "policy": ctx["policy"]}}
    a = obj.artifact or {}
    return {"model": {"name": obj.name, "format": a.get("format"), "sha256": a.get("sha256"), "version": a.get("version"),
                      "signed": a.get("signed"), "signatureValid": a.get("signatureValid")},
            "controls": {"policy": ctx["policy"]}}


def _fp(inp: dict) -> str:
    return hashlib.sha256(json.dumps(inp, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:16]


KIND_L = {"chatbot": ("상담 챗봇", "chatbot"), "coding_agent": ("코딩 에이전트", "coding agent"), "workflow": ("업무 에이전트", "workflow agent"),
          "rag": ("검색 증강(RAG)", "RAG system"), "other": ("AI 시스템", "AI system")}


def _sections(s: Session, tenant: str, kind: str, obj, inp: dict) -> dict:
    """카드 본문 — 섹션마다 ko·en 병기(NFR-C4). 원문·개인정보 없음."""
    def kv(ko: str, en: str) -> dict:
        return {"ko": ko, "en": en}
    rt = redteam.latest(s)
    res = {r["agent"]: r for r in ((rt.body.get("results") if rt else None) or [])}
    if kind == "system":
        c = inp["controls"]
        app_ = profiles.active_for(s, tenant, obj.name)
        ev = [res[a] for a in (app_.agent_ids if app_ else []) if a in res]
        det = round(sum(r["detectionRate"] for r in ev) / len(ev), 3) if ev else None
        fpr = round(sum(r.get("fpRate", 0) for r in ev) / len(ev), 4) if ev else None
        fm = next(iter(r for r in _hist(s, tenant, "fairness", obj.name, 1)), None)
        over = (fm.body.get("over") or {}) if fm else {}
        k_ko, k_en = KIND_L.get(obj.kind, KIND_L["other"])
        data = ", ".join(n if v == "—" else f"{n} {v}" for n, v in inp["data"].items())
        return {
            "purpose": kv(f"{k_ko} — {obj.endpoint} ({obj.insertion}). 고위험·금전 행동은 사람 승인 경유, 최종 결정은 사람.",
                          f"{k_en} — {obj.endpoint} ({obj.insertion}). High-risk and monetary actions go through human approval; people make the final call."),
            "model": kv(f"{'외부 공급자 ' + obj.model_provider if obj.external_model else '자체 호스팅'}", f"{'external provider ' + obj.model_provider if obj.external_model else 'self-hosted'}"),
            "data": kv(f"검색·학습 데이터: {data}" if data else "등록된 데이터셋 없음 (D7 무결성 점검 대상으로 등록)",
                       f"Retrieval/training data: {data}" if data else "No registered datasets (register them as D7 integrity scan targets)"),
            "evaluation": kv(f"레드팀 코퍼스 탐지율 {det} · 오탐 {fpr} (에이전트 {len(ev)}종)" if ev else "평가 결과 없음 — 레드팀 캠페인 실행",
                             f"Red-team corpus detection {det} · false positives {fpr} ({len(ev)} agents)" if ev else "No evaluation yet — run a red-team campaign"),
            "limits": kv("규칙·통계 엔진 — 시험 코퍼스 밖 변형은 미탐 가능. 원문 미보존(근거 구간만)." + "".join(f" {ax} 집단 차단율 격차 {v['gapPp']:.2f}%p (N06)." for ax, v in over.items()),
                         "Rule/statistical engines — variants outside the test corpus may be missed. No raw text kept (evidence spans only)." + "".join(f" {ax} group block-rate gap {v['gapPp']:.2f}pp (N06)." for ax, v in over.items())),
            "controls": kv(f"관문 4 · 에이전트 {c['agents']}종 · 프로파일 {c['profile'] or '미적용'}({c['stage'] or '—'}) · 정책 {c['policy']}",
                           f"4 gates · {c['agents']} agents · profile {c['profile'] or 'none'} ({c['stage'] or '—'}) · policy {c['policy']}"),
            "fairness": kv(f"최근 측정 {fm.created_at[:10]} · 최대 격차 " + (", ".join(f"{ax} {v['gapPp']:.2f}%p" for ax, v in (fm.body.get('gaps') or {}).items()) or "—") if fm else "측정 없음 — 공정성 지표(N06)에서 측정",
                           f"Measured {fm.created_at[:10]} · max gaps " + (", ".join(f"{ax} {v['gapPp']:.2f}pp" for ax, v in (fm.body.get('gaps') or {}).items()) or "—") if fm else "Not measured — measure in Fairness (N06)"),
        }
    m = inp["model"]
    return {
        "purpose": kv(f"모델 구성요소 {m['name']} — 보호 대상이 쓰는 모델(점검 대상 등록)", f"Model component {m['name']} — used by protected targets (registered scan target)"),
        "model": kv(f"형식 {m['format'] or '—'} · 버전 {m['version'] or '—'} · sha256 {str(m['sha256'] or '—')[:16]}", f"format {m['format'] or '—'} · version {m['version'] or '—'} · sha256 {str(m['sha256'] or '—')[:16]}"),
        "data": kv("학습 데이터 출처는 공급자 문서 참조 — 플랫폼은 해시·서명만 확인", "Training data provenance per the supplier's documentation — the platform checks hash and signature only"),
        "evaluation": kv(f"최근 무결성 점검 {obj.last_verdict or '없음'}", f"Last integrity scan {obj.last_verdict or 'none'}"),
        "limits": kv("직렬화 형식의 위험 전역(pickle) 탐지는 정적 분석 — 동적 로딩 동작은 격리 심사(R4) 범위", "Dangerous pickle globals are found statically — runtime loading behaviour is covered by sandbox review (R4)"),
        "controls": kv(f"해시 고정·서명 검증({'✓' if m['signed'] and m['signatureValid'] else '✗'}) · D7-03/04 상시 점검 · 정책 {inp['controls']['policy']}",
                       f"Hash pin · signature ({'✓' if m['signed'] and m['signatureValid'] else '✗'}) · D7-03/04 continuous scans · policy {inp['controls']['policy']}"),
        "fairness": kv("해당 없음 — 시스템 카드의 공정성 지표 참조", "N/A — see the system card's fairness metrics"),
    }


def _card_hist(s: Session, tenant: str, subject: str) -> list[models.Evidence]:
    return list(reversed(_hist(s, tenant, "card", subject, 200)))


def _diff(old: dict, new: dict) -> list[str]:
    out = []
    for k in sorted(set(old) | set(new)):
        a, b = old.get(k), new.get(k)
        if a == b:
            continue
        if isinstance(a, dict) and isinstance(b, dict):
            out += [f"{k}.{x}: {a.get(x, '—')} → {b.get(x, '—')}" for x in sorted(set(a) | set(b)) if a.get(x) != b.get(x)]
        else:
            out.append(f"{k}: {a} → {b}")
    return out


def generate(s: Session, tenant: str, by: str, only: str | None = None) -> list[dict]:
    """카드 자동 생성 — 입력 지문이 같으면 그대로, 다르면 새 판(초안). 바뀐 섹션을 표시한다."""
    ctx = _ctx(s, tenant)
    out = []
    for kind, name, obj in subjects(s, tenant, ctx):
        if only and name != only:
            continue
        inp = _inputs(s, tenant, kind, obj, ctx)
        fp = _fp(inp)
        gen = [r for r in _card_hist(s, tenant, name) if r.body.get("event") == "generated"]
        last = gen[-1].body if gen else None
        if last and last["fingerprint"] == fp:
            out.append({"subject": name, "type": kind, "version": last["version"], "created": False})
            continue
        changed = [k for k in inp if not last or last["inputs"].get(k) != inp[k]]
        ver = last["version"] + 1 if last else 1
        rec = ledger.append(s, "card", name, {"event": "generated", "subject": name, "type": kind, "version": ver, "fingerprint": fp,
                                              "inputs": inp, "sections": _sections(s, tenant, kind, obj, inp), "changed": changed, "by": by}, tenant)
        out.append({"subject": name, "type": kind, "version": ver, "created": True, "changed": changed, "seq": rec.seq})
    if only and not out:
        raise ComplianceError(404, f"카드 대상 {only} 없음")
    return out


def cards(s: Session, tenant: str) -> dict:
    ctx = _ctx(s, tenant)
    pend = {(a.action or {}).get("subject"): a.id for a in s.scalars(select(models.Approval).where(models.Approval.tenant == tenant, models.Approval.status == "pending"))
            if (a.action or {}).get("type") == "card_publish"}
    rows = []
    for kind, name, obj in subjects(s, tenant, ctx):
        inp = _inputs(s, tenant, kind, obj, ctx)
        hist = _card_hist(s, tenant, name)
        gen = [r for r in hist if r.body.get("event") == "generated"]
        pub = [r for r in hist if r.body.get("event") == "published"]
        last = gen[-1] if gen else None
        stale = last is not None and last.body["fingerprint"] != _fp(inp)
        status = "missing" if last is None else "needs-update" if stale else "review" if name in pend else \
            "latest" if pub and pub[-1].body.get("version") == last.body["version"] else "draft"
        rows.append({"subject": name, "type": kind, "status": status, "version": last.body["version"] if last else None,
                     "generatedAt": last.created_at if last else None, "sections": last.body["sections"] if last else None,
                     "changedSections": last.body.get("changed", []) if last else [], "changes": _diff(last.body["inputs"], inp) if stale else [],
                     "published": {"version": pub[-1].body["version"], "at": pub[-1].created_at, "audiences": pub[-1].body.get("audiences", [])} if pub else None,
                     "versions": [{"version": r.body["version"], "at": r.created_at, "changed": r.body.get("changed", [])} for r in gen][-10:],
                     "pending": pend.get(name), "langs": ["ko", "en"]})
    blocked = [r["subject"] for r in rows if r["status"] in ("missing", "needs-update")]
    return {"items": rows, "deployGate": {"ok": not blocked, "blocked": blocked}}


def card_doc(s: Session, tenant: str, subject: str, lang: str, version: int | None) -> str:
    gen = [r for r in _card_hist(s, tenant, subject) if r.body.get("event") == "generated" and (version is None or r.body["version"] == version)]
    if not gen:
        raise ComplianceError(404, f"카드 {subject}{f' v{version}' if version else ''} 없음")
    b = gen[-1].body
    title = {"system": ("시스템 카드", "System card"), "model": ("모델 카드", "Model card")}[b["type"]]
    heads = {"purpose": ("목적·사용 범위", "Purpose & scope"), "model": ("모델·버전", "Model & version"), "data": ("데이터", "Data"),
             "evaluation": ("평가 결과", "Evaluation"), "limits": ("제약·알려진 한계", "Limitations"), "controls": ("안전 통제", "Safety controls"),
             "fairness": ("공정성", "Fairness")}
    i = 0 if lang == "ko" else 1
    lines = [f"# {title[i]} — {subject} v{b['version']}", "", f"- {'생성' if i == 0 else 'Generated'}: {gen[-1].created_at} · {'지문' if i == 0 else 'fingerprint'} {b['fingerprint']}", ""]
    for k, h in heads.items():
        lines += [f"## {h[i]}", b["sections"][k][lang], ""]
    return "\n".join(lines)


def request_publish(s: Session, tenant: str, subject: str, audiences: list[str], by: str) -> dict:
    row = next((r for r in cards(s, tenant)["items"] if r["subject"] == subject), None)
    if row is None:
        raise ComplianceError(404, f"카드 대상 {subject} 없음")
    if row["status"] in ("missing", "needs-update"):
        raise ComplianceError(409, "카드 갱신(자동 생성) 먼저 — 변경 후 미갱신 카드는 공개할 수 없다 (MSG-021)")
    if row["pending"]:
        raise ComplianceError(409, f"검토 중 — 승인 요청 {row['pending']}")
    bad = [a for a in audiences if a not in AUDIENCES]
    if not audiences or bad:
        raise ComplianceError(422, f"공개 대상 {AUDIENCES} 중 1개 이상")
    a = approvals.create(s, secrets.token_hex(16), tenant, "offline", [], f"{subject} 카드 v{row['version']} 공개 — {', '.join(audiences)}", by,
                         required=1, action={"type": "card_publish", "subject": subject, "version": row["version"], "audiences": audiences})
    ledger.append(s, "card", subject, {"event": "review_requested", "version": row["version"], "audiences": audiences, "approval": a.id, "by": by}, tenant)
    return {"approvalRef": a.id, "subject": subject, "version": row["version"], "audiences": audiences}


def apply_publish(s: Session, row: models.Approval) -> dict:
    act = row.action or {}
    ledger.append(s, "card", act["subject"], {"event": "published", "version": act["version"], "audiences": act["audiences"],
                                              "by": f"approval:{row.id}"}, row.tenant)
    return {"applied": "card_publish", "subject": act["subject"], "version": act["version"], "audiences": act["audiences"]}


def platform_cards(s: Session) -> list[dict]:
    """거버넌스 스냅샷(D10-06)용 — 모든 테넌트의 시스템·모델 카드 존재·최신성(변경 시각 = 지금, 미갱신이면)."""
    now = utcnow().timestamp()
    out = []
    tenants = sorted(set(s.scalars(select(models.ProtectedTarget.tenant))) | set(s.scalars(select(models.ScanTarget.tenant).where(models.ScanTarget.kind == "model"))))
    for t in tenants:
        for r in cards(s, t)["items"]:
            out.append({"subject": f"{t}/{r['subject']}", "exists": r["status"] != "missing",
                        "updatedAt": iso_to_epoch(r["generatedAt"]) if r["generatedAt"] else None,
                        "changedAt": now if r["status"] == "needs-update" else None})
    return out


def deploy_gate(s: Session, tenant: str) -> dict:
    """배포 게이트(C4) — 레드팀 회귀 + 미갱신·누락 카드. 하나라도 있으면 차단."""
    rt = redteam.latest(s)
    regs = [r["agent"] for r in ((rt.body.get("regressions") if rt else None) or [])]
    c = cards(s, tenant)["deployGate"]["blocked"]
    reasons = [{"kind": "regression", "subject": a} for a in regs] + [{"kind": "card", "subject": x} for x in c]
    return {"ok": not reasons, "reasons": reasons}
