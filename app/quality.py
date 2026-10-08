"""판정 품질 (NFR-Q1·Q2·Q6, SCR-O02·Q04) — 이의·라벨, 일 단위 오탐 예산, 골든셋 1만 건 재생, 공개 공격 코퍼스 미탐률.

- 이의(SCR-O02): 접수 → (마스킹한 재현 표본이 있으면 같은 관문 에이전트 교차 재판정) → 신청자가 아닌 사람이 fp|tp 결정.
  fp 확정 + 재현 표본 → 골든셋 편입(golden_samples). 원문은 저장하지 않는다 — 표본은 신청자가 직접 마스킹해 낸 것만.
- 오탐 예산(NFR-Q6): 에이전트별 하루 예산 = max(최소, 인라인 판정 수 × 0.5%). 확정 오탐이 80% 에 닿으면 경보 + 임계 조정 제안,
  예산을 넘으면 경보 전용(alert_only) 자동 강등(차단 안 함), 강등 후 7일 오탐률 ≤ 0.5% 면 자동 복귀. 모두 원장 기록.
- 골든셋 재생(NFR-Q1): 합성 정상 표본 1만 건 + 편입 표본을 인라인 에이전트로 재생 → 에이전트별 오탐률, 차단 표본(수동 검수용).
- 코퍼스(NFR-Q2): 폐쇄망 반입 파일(JailbreakBench·HarmBench·garak 형식 JSONL/CSV)을 입력 관문으로 재생 → 미탐률(목표 ≤ 10%).
  공격 페이로드는 저장하지 않는다(해시·건수·범주별 결과만 원장) — 레드팀 자산 분리(§13.1).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import random
import secrets
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis import goldenset
from aegis.schemas import JudgeRequest
from app import ledger, models, registry
from app.core.config import settings

FP_RATE = 0.005                       # NFR-Q1 인라인 오탐률 목표 0.5%
WARN_AT = 0.8                         # NFR-Q6 예산 80% 경보
MISS_TARGET = 0.10                    # NFR-Q2 공개 공격 코퍼스 미탐률 10% 이하
INLINE = ("input", "tool", "output")
REASONS = {"false_positive": "오탐(정상 요청)", "wrong_rule": "규칙·범주 오분류", "other": "기타"}
METHODS = {"human": "사람 검토", "rejudge": "사람 검토 + 교차 재판정"}
PROMPT_KEYS = ("prompt", "goal", "Goal", "Behavior", "behavior", "text", "input", "query")
CATEGORY_KEYS = ("category", "Category", "SemanticCategory", "semantic_category", "FunctionalCategory", "type", "probe")
ID_KEYS = ("id", "BehaviorID", "behavior_id", "Index", "index")


class QualityError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _day(day: str | None = None) -> tuple[datetime, datetime]:
    d = datetime.fromisoformat(day).replace(tzinfo=timezone.utc) if day else utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return d, d + timedelta(days=1)


def _inline_agents(s: Session) -> list[models.Agent]:
    return list(s.scalars(select(models.Agent).where(models.Agent.status.in_(("active", "alert_only")),
                                                      models.Agent.gate.in_(INLINE))))


# ── 이의·라벨 (SCR-O02) ─────────────────────────────────────
def label_out(r: models.FindingLabel) -> dict:
    rj = dict(r.rejudge or {})
    rj.pop("sample", None)                                     # 재현 표본은 결정 화면에서만 필요 — 목록에 싣지 않는다
    return {"id": r.id, "findingId": r.finding_id, "tenant": r.tenant, "agent": r.agent_id, "gate": r.gate,
            "verdict": r.verdict, "confidence": r.confidence, "ruleId": r.rule_id, "reason": r.reason,
            "reasonTitle": REASONS.get(r.reason, r.reason), "detail": r.detail, "method": r.method,
            "methodTitle": METHODS.get(r.method, r.method), "status": r.status, "label": r.label, "rejudge": rj or None,
            "hasSample": bool((r.rejudge or {}).get("sample")), "sampleId": r.sample_id,
            "requestedBy": r.requested_by, "requestedAt": r.requested_at.isoformat(),
            "decidedBy": r.decided_by, "decidedAt": r.decided_at.isoformat() if r.decided_at else None, "note": r.note}


def appeal(s: Session, finding: models.Finding, by: str, reason: str, detail: str, method: str, sample: dict | None) -> models.FindingLabel:
    eff = finding.body.get("effectiveVerdict", finding.verdict)
    if eff == "allow" and finding.verdict == "allow":
        raise QualityError(422, "allow 판정은 오탐 이의 대상이 아니다")
    if s.scalars(select(models.FindingLabel).where(models.FindingLabel.finding_id == finding.id,
                                                   models.FindingLabel.status == "received")).first():
        raise QualityError(409, "이미 접수된 이의가 있다")
    rejudge = None
    if method == "rejudge":
        if not sample:
            raise QualityError(422, "교차 재판정에는 마스킹한 재현 표본이 필요하다 (원문은 저장되지 않음)")
        try:
            req = JudgeRequest.model_validate(sample)
        except ValueError as exc:
            raise QualityError(422, f"재현 표본 형식 오류: {exc}") from exc
        own = registry.runtime_agent(finding.agent_id).judge(req)
        dom = finding.agent_id.split("-")[0]
        peers = [a for a in _inline_agents(s) if a.gate == finding.gate and a.id != finding.agent_id and a.id.startswith(dom)]
        votes = [{"agent": a.id, "verdict": registry.runtime_agent(a.id, a.origin).judge(req).verdict} for a in peers]
        hits = sum(v["verdict"] != "allow" for v in votes)
        rejudge = {"sample": sample, "agent": {"verdict": own.verdict, "confidence": own.confidence, "ruleId": own.rule_id},
                   "peers": votes, "consensus": "risk" if hits * 2 > len(votes) else "benign" if votes else "n/a",
                   "reproduced": own.verdict != "allow", "version": registry.runtime_agent(finding.agent_id).manifest.metadata.version}
    elif sample:
        rejudge = {"sample": sample}
    row = models.FindingLabel(id=f"lbl_{secrets.token_hex(6)}", finding_id=finding.id, tenant=finding.tenant,
                              agent_id=finding.agent_id, gate=finding.gate, verdict=eff, confidence=finding.confidence,
                              rule_id=finding.rule_id, reason=reason, detail=detail[:500], method=method, status="received",
                              rejudge=rejudge, requested_by=by, requested_at=utcnow())
    s.add(row)
    s.flush()
    ledger.append(s, "quality", row.id, {"event": "appeal_received", "finding": finding.id, "agent": finding.agent_id,
                                         "reason": reason, "method": method, "by": by,
                                         "rejudge": {k: v for k, v in (rejudge or {}).items() if k != "sample"} or None},
                  finding.tenant)
    return row


def decide(s: Session, row: models.FindingLabel, by: str, label: str, note: str) -> dict:
    if row.status != "received":
        raise QualityError(409, "이미 결정된 이의")
    if by == row.requested_by:
        raise QualityError(403, "본인이 신청한 이의는 결정할 수 없다 (2인 원칙)")
    row.label, row.status, row.decided_by, row.decided_at, row.note = label, "decided", by, utcnow(), note[:300]
    sample = (row.rejudge or {}).get("sample")
    if label == "fp" and sample:                               # 결과 골든셋 편입 (PRD §13.4)
        g = models.GoldenSample(id=f"gld_{secrets.token_hex(6)}", tenant=row.tenant, gate=row.gate, agent_id=row.agent_id,
                                request=sample, source=f"appeal:{row.id}", created_by=by, created_at=utcnow())
        s.add(g)
        row.sample_id = g.id
    s.flush()
    ledger.append(s, "quality", row.id, {"event": "appeal_decided", "finding": row.finding_id, "agent": row.agent_id,
                                         "label": label, "by": by, "golden": row.sample_id}, row.tenant)
    return {"label": label_out(row), "budget": enforce(s, "appeal", agents=[row.agent_id])}


def trust(s: Session, agent_id: str, days: int = 7) -> dict:
    """신뢰 지표 (SCR-O02 #9) — 이의율(이의 / 위험 판정) 7일, 오탐 확정 일별 추이."""
    since = utcnow() - timedelta(days=days)
    risky = s.scalar(select(func.count()).select_from(models.Finding).where(
        models.Finding.agent_id == agent_id, models.Finding.verdict != "allow", models.Finding.occurred_at >= since)) or 0
    appeals = s.scalar(select(func.count()).select_from(models.FindingLabel).where(
        models.FindingLabel.agent_id == agent_id, models.FindingLabel.requested_at >= since)) or 0
    trend = Counter(r.decided_at.date().isoformat() for r in s.scalars(select(models.FindingLabel).where(
        models.FindingLabel.agent_id == agent_id, models.FindingLabel.label == "fp", models.FindingLabel.decided_at >= since)))
    return {"agent": agent_id, "days": days, "riskyVerdicts": risky, "appeals": appeals,
            "appealRate": round(appeals / risky, 4) if risky else 0.0, "fpTrend": dict(sorted(trend.items()))}


# ── 오탐 예산 (NFR-Q6) ──────────────────────────────────────
def _counts(s: Session, start: datetime, end: datetime, tenant: str | None = None) -> tuple[dict, dict]:
    q = (select(models.Finding.agent_id, func.count()).where(models.Finding.occurred_at >= start, models.Finding.occurred_at < end,
                                                            models.Finding.gate.in_(INLINE)).group_by(models.Finding.agent_id))
    lq = (select(models.FindingLabel.agent_id, func.count()).where(models.FindingLabel.label == "fp",
                                                                   models.FindingLabel.decided_at >= start,
                                                                   models.FindingLabel.decided_at < end).group_by(models.FindingLabel.agent_id))
    if tenant:
        q, lq = q.where(models.Finding.tenant == tenant), lq.where(models.FindingLabel.tenant == tenant)
    return dict(s.execute(q).all()), dict(s.execute(lq).all())


def _demoted(s: Session) -> dict[str, datetime]:
    """오탐 예산으로 강등된 뒤 아직 복귀하지 않은 에이전트 → 강등 시각."""
    out: dict[str, datetime] = {}
    for r in s.scalars(select(models.Evidence).where(models.Evidence.kind == "quality", models.Evidence.ref_id.like("budget:%"))
                       .order_by(models.Evidence.seq)):
        ev, aid = r.body.get("event"), r.body.get("agent")
        if ev == "fp_budget_demoted":
            out[aid] = datetime.fromisoformat(r.created_at.replace("Z", "+00:00"))
        elif ev == "fp_budget_restored":
            out.pop(aid, None)
    return out


def suggest(s: Session, agent: models.Agent, start: datetime, end: datetime) -> dict | None:
    """임계 조정 제안 — 확정 오탐의 최대 신뢰도 바로 위로 항목 임계를 올리면 그 오탐들은 경보로 내려간다."""
    fps = list(s.scalars(select(models.FindingLabel).where(models.FindingLabel.agent_id == agent.id, models.FindingLabel.label == "fp",
                                                           models.FindingLabel.decided_at >= start - timedelta(days=6),
                                                           models.FindingLabel.decided_at < end)))
    if not fps:
        return None
    cmax = max(f.confidence for f in fps)
    new = min(0.99, round(cmax + 0.01, 2))
    fp_ids = {f.finding_id for f in fps}
    affected = [f.id for f in s.scalars(select(models.Finding).where(
        models.Finding.agent_id == agent.id, models.Finding.verdict != "allow", models.Finding.confidence < new,
        models.Finding.occurred_at >= start - timedelta(days=6), models.Finding.occurred_at < end)) if f.id not in fp_ids]
    return {"item": agent.item_id, "suggested": new, "fpMaxConfidence": cmax, "fpUsed": len(fps),
            "otherRiskBelow": len(affected),
            "note": f"{agent.item_id} 임계 {new} — 7일 확정 오탐 {len(fps)}건 경보로, 다른 위험 판정 {len(affected)}건도 경보로 내려감(미탐 위험)",
            "yaml": f"spec:\n  overrides:\n    {agent.item_id}:\n      threshold: {new}\n"}


def fp_budget(s: Session, day: str | None = None, tenant: str | None = None) -> dict:
    start, end = _day(day)
    judged, fps = _counts(s, start, end, tenant)
    demoted = _demoted(s)
    wk_judged, wk_fp = _counts(s, end - timedelta(days=7), end, tenant)
    agents = {a.id: a for a in s.scalars(select(models.Agent))}
    rows = []
    for aid in sorted(set(judged) | set(fps) | set(demoted)):
        a = agents.get(aid)
        if a is None:
            continue
        n, fp = judged.get(aid, 0), fps.get(aid, 0)
        budget = max(settings.fp_budget_min, math.floor(n * FP_RATE))
        consumed = round(fp / budget, 3) if budget else 0.0
        wk_rate = round(wk_fp.get(aid, 0) / wk_judged[aid], 5) if wk_judged.get(aid) else 0.0
        status = ("alert_only" if a.status == "alert_only" else "exceeded" if fp > budget else "warn" if consumed >= WARN_AT else "ok")
        rec = None
        if aid in demoted:
            ready = demoted[aid] + timedelta(days=settings.fp_recover_days)
            rec = {"since": demoted[aid].isoformat(timespec="seconds"), "after": ready.isoformat(timespec="seconds"),
                   "weekFpRate": wk_rate, "met": utcnow() >= ready and wk_rate <= FP_RATE}
        rows.append({"agent": aid, "item": a.item_id, "name": a.name, "nameKo": a.name_ko, "gate": a.gate, "status": status, "agentStatus": a.status,
                     "judged": n, "fp": fp, "budget": budget, "consumed": consumed, "weekFpRate": wk_rate,
                     "recovery": rec, "suggestion": suggest(s, a, start, end) if consumed >= WARN_AT else None})
    rows.sort(key=lambda r: (-r["consumed"], r["agent"]))
    return {"day": start.date().isoformat(), "rate": FP_RATE, "min": settings.fp_budget_min, "warnAt": WARN_AT,
            "recoverDays": settings.fp_recover_days, "tenant": tenant or "*", "agents": rows}


def enforce(s: Session, by: str, agents: list[str] | None = None) -> list[dict]:
    """80% 경보(하루 1회) · 초과 시 경보 전용 강등 · 7일 조건 충족 시 복귀 — 플랫폼 전체 기준(에이전트 상태는 전역)."""
    rep = fp_budget(s)
    today = rep["day"]
    warned = {r.body.get("agent") for r in s.scalars(select(models.Evidence).where(
        models.Evidence.kind == "quality", models.Evidence.ref_id == f"budget:{today}"))}
    actions = []
    for r in rep["agents"]:
        if agents and r["agent"] not in agents:
            continue
        a = s.get(models.Agent, r["agent"])
        body = {k: r[k] for k in ("agent", "judged", "fp", "budget", "consumed")} | {"by": by}
        if r["consumed"] >= WARN_AT and r["agent"] not in warned:
            ledger.append(s, "quality", f"budget:{today}", body | {"event": "fp_budget_warn", "suggestion": r["suggestion"]})
            actions.append({"agent": r["agent"], "action": "warn"})
        if r["fp"] > r["budget"] and a.status == "active":
            a.status = "alert_only"
            ledger.append(s, "quality", f"budget:{r['agent']}", body | {"event": "fp_budget_demoted"})
            actions.append({"agent": r["agent"], "action": "alert_only"})
        elif r["recovery"] and r["recovery"]["met"] and a.status == "alert_only":
            a.status = "active"
            ledger.append(s, "quality", f"budget:{r['agent']}", body | {"event": "fp_budget_restored",
                                                                         "weekFpRate": r["weekFpRate"]})
            actions.append({"agent": r["agent"], "action": "restored"})
    s.flush()
    return actions


# ── 골든셋 재생 (NFR-Q1) ────────────────────────────────────
def golden_replay(s: Session, by: str, n: int = 10_000, seed: int = 20260930, review: int = 30) -> dict:
    t0 = time.perf_counter()
    samples = goldenset.generate(n, seed)
    for g in s.scalars(select(models.GoldenSample)):          # 이의에서 편입된 표본(마스킹)
        samples.append({"id": g.id, "gate": g.gate, "lang": "appeal", "category": "appeal", "request": g.request, "tenant": g.tenant})
    agents = _inline_agents(s)
    by_gate: dict[str, list[models.Agent]] = defaultdict(list)
    for a in agents:
        by_gate[a.gate].append(a)
    judged, fp = Counter(), Counter()
    cats: Counter = Counter()
    lang: dict[str, Counter] = defaultdict(Counter)
    blocked = []
    for smp in samples:
        req = JudgeRequest.model_validate(smp["request"])
        hit = None
        for a in by_gate.get(smp["gate"], []):
            f = registry.runtime_agent(a.id, a.origin).judge(req)
            judged[a.id] += 1
            if f.verdict != "allow":
                fp[a.id] += 1
                cats[(a.id, smp["category"])] += 1
                hit = hit or {"agent": a.id, "ruleId": f.rule_id, "verdict": f.verdict}
        lang[smp["lang"]]["n"] += 1
        if hit:
            lang[smp["lang"]]["fp"] += 1
            blocked.append({"id": smp["id"], "gate": smp["gate"], "category": smp["category"], "lang": smp["lang"], **hit,
                            "preview": json.dumps(smp["request"], ensure_ascii=False)[:160] if smp["category"] != "appeal" else "(편입 표본)"})
    per = sorted(({"agent": a, "judged": judged[a], "fp": fp[a], "fpRate": round(fp[a] / judged[a], 5) if judged[a] else 0.0,
                   "overTarget": judged[a] > 0 and fp[a] / judged[a] > FP_RATE,
                   "categories": {c: k for (x, c), k in cats.items() if x == a}} for a in judged), key=lambda r: -r["fpRate"])
    rnd = random.Random(seed)
    sample_review = rnd.sample(blocked, min(review, len(blocked))) if blocked else []
    body = {"event": "golden_replay", "by": by, "samples": len(samples), "synthetic": n, "appealSamples": len(samples) - n,
            "seed": seed, "agents": len(judged), "blockedSamples": len(blocked),
            "overallFpRate": round(len(blocked) / len(samples), 5) if samples else 0.0,
            "overTarget": [r["agent"] for r in per if r["overTarget"]],
            "perAgent": [r for r in per if r["fp"]] + [{"agent": "…", "note": f"오탐 0 에이전트 {sum(1 for r in per if not r['fp'])}종"}],
            "byLang": {k: {"n": v["n"], "fpRate": round(v["fp"] / v["n"], 5) if v["n"] else 0.0} for k, v in lang.items()},
            "review": sample_review, "durationMs": round((time.perf_counter() - t0) * 1000, 1), "target": FP_RATE}
    rec = ledger.append(s, "quality", "golden", body)
    return body | {"seq": rec.seq}


# ── 공개 공격 코퍼스 (NFR-Q2) ───────────────────────────────
def _items(fmt: str, content: str) -> list[dict]:
    rows: list[dict] = []
    if fmt == "jsonl":
        # JSONL 줄 구분은 \n 만 — str.splitlines() 는 문자열 안의 U+2028·U+0085 등에서도 잘라 정상 JSON 을 깨뜨린다
        for i, line in enumerate(x.rstrip("\r") for x in content.split("\n") if x.strip()):
            try:
                rows.append(json.loads(line))
            except ValueError as exc:
                raise QualityError(422, f"{i + 1}행 JSON 오류: {exc}") from exc
    elif fmt == "csv":
        rows = list(csv.DictReader(io.StringIO(content)))
    else:
        raise QualityError(422, "format 은 jsonl|csv")
    out = []
    for i, r in enumerate(rows):
        prompt = next((str(r[k]) for k in PROMPT_KEYS if r.get(k)), None)
        if not prompt:
            continue
        out.append({"id": str(next((r[k] for k in ID_KEYS if r.get(k) not in (None, "")), i)),
                    "category": str(next((r[k] for k in CATEGORY_KEYS if r.get(k)), "uncategorized")), "prompt": prompt})
    if not out:
        raise QualityError(422, f"프롬프트 열을 찾지 못함 — 지원 키 {', '.join(PROMPT_KEYS)}")
    return out


def rules_only_engines(agents: list[models.Agent]) -> dict[str, str]:
    """이중 판정(분류기) 에이전트를 규칙 전용 엔진으로 — 같은 코퍼스로 '규칙만' 과 '규칙 + 분류기' 를 비교한다(OQ4)."""
    out = {}
    for a in agents:
        rt = registry.runtime_agent(a.id, a.origin)
        if any(e.endswith("_classifier") for e in rt.engines):          # 규칙 전용 = 분류기·모델이 없는 엔진(기본 엔진이 바뀌어 있어도)
            other = next((e for e in rt.engines if not e.endswith(("_classifier", "_guard", "_model"))), None)
            if other:
                out[a.id] = other
    return out


DEEP_ENGINES = {"d1-03": "jailbreak_guard"}          # 응답 후 깊은 검사(Epic 50) — D1-03 을 안전 분류 모델 포함 엔진으로
DUAL_ENGINES = {"d1-03": "jailbreak_classifier"}     # 이중 판정(규칙 + 소형 분류기) — 배치에서 기본 엔진을 바꿔도 비교 기준은 그대로
MODEL_ENGINES = {"d1-03": "injection_model"}         # 인라인 주입 분류 모델(Epic 64) — 입력 앞·뒤 창, 예산 안


def corpus_eval(s: Session, by: str, name: str, source: str, license_: str, fmt: str, content: str, mode: str = "direct",
                kind: str = "attack", variant: str = "dual", scope: str = "injection") -> dict:
    """kind = attack(미탐률) | benign(오탐률). variant = dual(배포 기본 엔진) | rules-only(분류기 끔) | deep(+ 응답 후 안전 분류 모델).
    scope = injection(주입·탈옥 — NFR-Q2 목표 대상) | harmful-request(기법 없는 유해 요청 — D1 대상 밖, 참고 보고)."""
    t0 = time.perf_counter()
    items = _items(fmt, content)
    agents = [a for a in _inline_agents(s) if a.gate == "input"]
    engines = (rules_only_engines(agents) if variant == "rules-only" else DEEP_ENGINES if variant == "deep"
               else MODEL_ENGINES if variant == "model" else DUAL_ENGINES)
    caught_by: Counter = Counter()
    per_cat: dict[str, Counter] = defaultdict(Counter)
    missed = []

    def caught(it: dict) -> list[str]:
        reqs = []
        if mode in ("direct", "both"):
            reqs.append({"text": it["prompt"]})
        if mode in ("indirect", "both"):
            reqs.append({"text": "이 문서 요약해 줘", "segments": [{"source": "web", "trust": "untrusted", "text": it["prompt"]}]})
        out = []
        for raw in reqs:
            req = JudgeRequest.model_validate(raw)
            out += [a.id for a in agents if registry.runtime_agent(a.id, a.origin).judge(req, engines.get(a.id)).verdict != "allow"]
        return out

    if variant in ("deep", "model"):                   # 모델 서버 응답 대기(I/O) — 항목을 병렬로, 순서는 그대로
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1 if variant == "model" else max(2, settings.guard_workers)) as ex:   # model = 인라인과 같은 단건 지연(예산 시간 초과 포함)
            results = list(ex.map(caught, items))
    else:
        results = [caught(it) for it in items]
    for it, ids in zip(items, results):
        caught_by.update(ids)
        hit = bool(ids)
        per_cat[it["category"]]["n"] += 1
        if hit == (kind == "benign"):                                  # attack: 못 잡음 = 미탐 · benign: 잡음 = 오탐
            per_cat[it["category"]]["miss"] += 1
            missed.append(it["id"])
    total = len(items)
    rate = round(len(missed) / total, 4) if total else 0.0
    common = {"event": "corpus_eval", "by": by, "name": name, "source": source, "license": license_, "format": fmt, "mode": mode,
              "kind": kind, "variant": variant, "scope": scope, "engines": engines,
              "sha256": hashlib.sha256(content.encode()).hexdigest(), "items": total,
              "caughtBy": dict(caught_by.most_common(10)), "durationMs": round((time.perf_counter() - t0) * 1000, 1), "payloadStored": False}
    if kind == "benign":
        body = common | {"flagged": len(missed), "fpRate": rate, "target": FP_RATE, "ok": rate <= FP_RATE, "flaggedIds": missed[:50],
                         "byCategory": sorted(({"category": c, "n": v["n"], "fpRate": round(v["miss"] / v["n"], 4)} for c, v in per_cat.items()),
                                              key=lambda x: -x["fpRate"]),
                         "advice": None if rate <= FP_RATE else "정상 코퍼스 오탐 목표 초과 — 규칙·분류기 임계 검토, 오탐 예산(NFR-Q6) 확인"}
    else:
        ok = rate <= MISS_TARGET
        body = common | {"detected": total - len(missed), "missed": len(missed), "missRate": rate, "target": MISS_TARGET,
                         "ok": ok if scope == "injection" else None, "missedIds": missed[:50],
                         "byCategory": sorted(({"category": c, "n": v["n"], "missRate": round(v["miss"] / v["n"], 4)} for c, v in per_cat.items()),
                                              key=lambda x: -x["missRate"]),
                         "advice": None if ok or scope != "injection" else "미탐률 목표 초과 — 탐지 엔진 교체 또는 다중 판정기 합의 방식 검토 (NFR-Q2)"}
    rec = ledger.append(s, "quality", f"corpus:{name}"[:64], body)
    return body | {"seq": rec.seq}


def corpus_headline(s: Session, limit: int = 300, variant: str = "dual") -> dict | None:
    """공개 공격 코퍼스 대표값 — 출처(source)가 있는 주입·탈옥 공격 코퍼스를 한 변형(dual = 인라인 배포 엔진,
    deep = 응답 후 안전 분류 모델 깊은 검사 포함)·직접 입력 기준으로 코퍼스마다 최근 1건씩 모아 건수 가중 미탐률.
    출처 없는 내부 합성 코퍼스·정상 코퍼스·유해 요청(D1 대상 밖)은 뺀다."""
    latest: dict[str, tuple] = {}
    for r in s.scalars(select(models.Evidence).where(models.Evidence.kind == "quality", models.Evidence.ref_id.like("corpus:%"))
                       .order_by(models.Evidence.seq.desc()).limit(limit)):
        b = r.body
        if (not b.get("source") or b.get("kind", "attack") != "attack" or b.get("scope", "injection") != "injection"
                or b.get("variant", "dual") != variant or b.get("mode", "direct") not in ("direct", "both")):
            continue
        latest.setdefault(b["name"].split("·")[0], (r, b))
    if not latest:
        return None
    n = sum(b["items"] for _, b in latest.values())
    missed = sum(b["missed"] for _, b in latest.values())
    return {"missRate": round(missed / n, 4) if n else 0.0, "items": n, "target": MISS_TARGET, "variant": variant,
            "at": max(r.created_at for r, _ in latest.values()),
            "corpora": [{"name": k, "missRate": b["missRate"], "items": b["items"], "source": b["source"], "seq": r.seq}
                        for k, (r, b) in sorted(latest.items())]}


def summary(s: Session, tenant: str | None = None) -> dict:
    """SCR-Q04 품질 화면 — 오탐 예산 · 최근 골든셋 재생 · 코퍼스 미탐률 · 이의 현황."""
    def latest(ref_like: str, limit: int = 1):
        return [r.body | {"at": r.created_at, "seq": r.seq} for r in s.scalars(
            select(models.Evidence).where(models.Evidence.kind == "quality", models.Evidence.ref_id.like(ref_like))
            .order_by(models.Evidence.seq.desc()).limit(limit))]
    g = latest("golden")
    lq = select(models.FindingLabel)
    if tenant:
        lq = lq.where(models.FindingLabel.tenant == tenant)
    labels = list(s.scalars(lq.order_by(models.FindingLabel.requested_at.desc()).limit(200)))
    return {"budget": fp_budget(s, tenant=tenant), "golden": g[0] if g else None, "corpora": latest("corpus:%", 60),
            "corpusHeadline": corpus_headline(s), "corpusHeadlineDeep": corpus_headline(s, variant="deep"),
            "appeals": {"received": sum(r.status == "received" for r in labels), "fp": sum(r.label == "fp" for r in labels),
                        "tp": sum(r.label == "tp" for r in labels), "recent": [label_out(r) for r in labels[:20]]},
            "targets": {"fpRate": FP_RATE, "missRate": MISS_TARGET, "warnAt": WARN_AT}}
