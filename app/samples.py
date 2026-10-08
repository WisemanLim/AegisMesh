"""미리보기용 실제 트래픽 표본 (OQ1 결정 · NFR-D1 · R01·R07 · SCR-C06).

기본은 미보존(NFR-D1). 테넌트가 켜면(켜기·늘리기 = 2인 승인) 관문 판정 요청을 **수집 단계에서 마스킹**해 최근 N건·D일만 둔다.
마스킹 = 관측 파이프라인과 같은 규칙(observability/masking.yaml) + 주체 식별자 가명화 + 인증·세션 값 제거.
미리보기는 이 표본을 선택 프로파일로 다시 판정하고, 사람이 붙인 라벨(정상·공격)로 오탐·미탐을 추정한다. 끄면 즉시 전부 삭제.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app import approvals, hotcache, ledger, models, telemetry
from app.auth import utcnow

DEFAULT = {"enabled": False, "maxSamples": 1000, "days": 7}
LIMITS = {"maxSamples": (10, 10000), "days": (1, 30)}
TEXT_KEYS = ("text", "system", "output", "goal")


class SampleError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def settings_of(s: Session, tenant: str) -> dict:
    t = s.get(models.Tenant, tenant)
    return DEFAULT | ((t.sample_retention or {}) if t else {})


def enabled(s: Session, tenant: str) -> dict | None:
    """인라인 경로용 — 켜져 있으면 설정, 아니면 None (캐시 2초, 테넌트 변경 커밋 시 무효화)."""
    cfg = hotcache.get(("samples", tenant), lambda: settings_of(s, tenant))
    return cfg if cfg.get("enabled") else None


def _h8(v) -> str:
    return "p:" + hashlib.sha256(str(v).encode()).hexdigest()[:8]


def _mask_str(v: str, hits: set) -> str:
    out, names = telemetry.mask(v[:8000])
    hits.update(names)
    return out


def mask_request(req: dict) -> tuple[dict, list[str]]:
    """요청 사본 — 글자 필드 마스킹, 주체 식별자 가명, 인증·세션·토큰 제거(원값을 남기지 않는다)."""
    hits: set = set()
    r = {k: v for k, v in req.items() if k not in ("auth", "session", "traceId", "trace_id")}
    for k in TEXT_KEYS:
        if isinstance(r.get(k), str):
            r[k] = _mask_str(r[k], hits)
    for k in ("segments", "retrieval", "memory"):
        if isinstance(r.get(k), list):
            r[k] = [x | ({"text": _mask_str(x["text"], hits)} if isinstance(x.get("text"), str) else {})
                    | ({"owner": _h8(x["owner"])} if x.get("owner") else {}) for x in r[k] if isinstance(x, dict)][:20]
    if isinstance(r.get("tool"), dict):
        args = r["tool"].get("args") or {}
        r["tool"] = r["tool"] | {"args": {a: (_mask_str(v, hits) if isinstance(v, str) else v) for a, v in list(args.items())[:30]}}
    if isinstance(r.get("subject"), dict):
        sub = dict(r["subject"])
        for k in ("principal", "onBehalfOf"):
            if isinstance(sub.get(k), dict) and sub[k].get("id"):
                sub[k] = {"id": _h8(sub[k]["id"]), "type": sub[k].get("type", "user")}
        r["subject"] = {k: v for k, v in sub.items() if k in ("principal", "onBehalfOf", "groups", "resource")}
    return r, sorted(hits)


def capture(s: Session, tenant: str, cfg: dict, gate: str, target: str | None, profile: str | None, verdict: str, req) -> None:
    body, hits = mask_request(req.model_dump(by_alias=True, exclude_none=True, mode="json"))
    s.add(models.TrafficSample(id=f"smp_{secrets.token_hex(8)}", tenant=tenant, gate=gate, target=target, profile=profile, verdict=verdict,
                               request=body, masked=hits, expires_at=utcnow() + timedelta(days=int(cfg.get("days", 7)))))


def request_change(s: Session, tenant: str, enabled_: bool, max_samples: int, days: int, by: str) -> dict:
    for k, v in (("maxSamples", max_samples), ("days", days)):
        lo, hi = LIMITS[k]
        if not lo <= v <= hi:
            raise SampleError(422, f"{k} {lo}~{hi}")
    cur = settings_of(s, tenant)
    want = {"enabled": enabled_, "maxSamples": max_samples, "days": days}
    widen = enabled_ and (not cur["enabled"] or max_samples > cur["maxSamples"] or days > cur["days"])
    if widen:                                                           # 보존을 켜거나 늘림 = 개인정보 위험 증가 → 2인 승인(R07)
        a = approvals.create(s, secrets.token_hex(16), tenant, "offline", [], f"미리보기 표본 보존 {'켜기' if not cur['enabled'] else '확대'} — "
                             f"{max_samples}건·{days}일 (마스킹)", by, required=2, action={"type": "sample_retention", "tenant": tenant, **want})
        ledger.append(s, "privacy", "samples", {"event": "sample_retention_requested", "want": want, "approval": a.id, "by": by}, tenant)
        return {"status": "pending", "approvalRef": a.id, "current": cur, "want": want}
    removed = _apply(s, tenant, want, by)                                # 끄기·줄이기는 바로(위험 감소)
    return {"status": "applied", "current": settings_of(s, tenant), "removed": removed}


def _apply(s: Session, tenant: str, want: dict, by: str) -> int:
    t = s.get(models.Tenant, tenant)
    if t is None:
        raise SampleError(404, f"tenant {tenant} 없음")
    t.sample_retention = dict(want)
    removed = clear(s, tenant) if not want["enabled"] else trim(s, tenant)
    ledger.append(s, "privacy", "samples", {"event": "sample_retention_set", "settings": want, "removed": removed, "by": by}, tenant)
    hotcache.invalidate()
    return removed


def apply_action(s: Session, row: models.Approval) -> dict:
    act = row.action or {}
    want = {k: act[k] for k in ("enabled", "maxSamples", "days")}
    removed = _apply(s, act["tenant"], want, f"approval:{row.id}")
    return {"applied": "sample_retention", "tenant": act["tenant"], "settings": want, "removed": removed}


def clear(s: Session, tenant: str) -> int:
    return s.execute(delete(models.TrafficSample).where(models.TrafficSample.tenant == tenant)).rowcount or 0


def trim(s: Session, tenant: str | None = None) -> int:
    """만료 표본 삭제 + 테넌트별 최근 N건만 유지 (worker 주기·설정 변경 시)."""
    q = delete(models.TrafficSample).where(models.TrafficSample.expires_at < utcnow())
    n = s.execute(q.where(models.TrafficSample.tenant == tenant) if tenant else q).rowcount or 0
    tenants = [tenant] if tenant else list(s.scalars(select(models.TrafficSample.tenant).distinct()))
    for t in tenants:
        cap = settings_of(s, t)["maxSamples"] if settings_of(s, t)["enabled"] else 0
        keep = select(models.TrafficSample.id).where(models.TrafficSample.tenant == t).order_by(models.TrafficSample.created_at.desc()).limit(cap)
        n += s.execute(delete(models.TrafficSample).where(models.TrafficSample.tenant == t,
                                                          models.TrafficSample.id.not_in(keep.scalar_subquery()))).rowcount or 0
    return n


def out(r: models.TrafficSample) -> dict:
    return {"id": r.id, "gate": r.gate, "target": r.target, "profile": r.profile, "verdict": r.verdict, "request": r.request,
            "masked": r.masked, "label": r.label, "labeledBy": r.labeled_by, "createdAt": r.created_at.isoformat(), "expiresAt": r.expires_at.isoformat()}


def listing(s: Session, tenant: str, target: str | None, limit: int) -> dict:
    q = select(models.TrafficSample).where(models.TrafficSample.tenant == tenant)
    if target:
        q = q.where(models.TrafficSample.target == target)
    rows = list(s.scalars(q.order_by(models.TrafficSample.created_at.desc()).limit(limit)))
    total = s.scalar(select(func.count()).select_from(models.TrafficSample).where(models.TrafficSample.tenant == tenant)) or 0
    return {"settings": settings_of(s, tenant), "total": total, "items": [out(r) for r in rows],
            "labeled": {"benign": sum(r.label == "benign" for r in rows), "attack": sum(r.label == "attack" for r in rows)}}


def label(s: Session, tenant: str, sid: str, lab: str | None, by: str) -> dict:
    r = s.get(models.TrafficSample, sid)
    if r is None or r.tenant != tenant:
        raise SampleError(404, f"표본 {sid} 없음")
    r.label, r.labeled_by = lab, by if lab else None
    return out(r)


def for_preview(s: Session, tenant: str, target: str | None, limit: int = 400) -> list[dict]:
    q = select(models.TrafficSample).where(models.TrafficSample.tenant == tenant)
    if target:
        q = q.where(models.TrafficSample.target == target)
    return [{"gate": r.gate, "label": r.label, "source": "traffic", "name": r.id, "original": r.verdict, "request": r.request}
            for r in s.scalars(q.order_by(models.TrafficSample.created_at.desc()).limit(limit))]
