"""즉시 사용 마법사 (SCR-C04·C05·C07, FR-P12) — 보호 대상 등록, 프로파일 변경 비교, 단계 적용(부분 차단 도메인·전체 차단 승인),
프로파일 해제 = 이전 스냅샷 복귀."""
from __future__ import annotations

import re
import secrets
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import approvals, ledger, models, profiles
from app.models import utcnow

KINDS = ("chatbot", "coding_agent", "workflow", "rag", "other")
INSERTIONS = ("gateway", "sidecar", "sdk")
ENDPOINT = re.compile(r"^(https?://)?[A-Za-z0-9.-]+(:\d{1,5})?(/[\w./-]*)?$")
HOST = re.compile(r"^[A-Za-z0-9.-]+(:\d{1,5})?$")


class InstantError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _region(s: Session, pid: str | None) -> dict:
    if not pid:
        return {}
    sp = profiles._spec(s, pid)
    while not sp.get("region") and sp.get("extends"):
        sp = profiles._spec(s, sp["extends"])
    return sp.get("region") or {}


def _evidence(s: Session, pid: str) -> dict:
    sp = profiles._spec(s, pid)
    while not sp.get("evidence") and sp.get("extends"):
        sp = profiles._spec(s, sp["extends"])
    return sp.get("evidence") or {}


# ── ② 보호 대상 (SCR-C05) ──────────────────────────────────────
def target_out(s: Session, t: models.ProtectedTarget) -> dict:
    since = (utcnow() - timedelta(hours=24)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    app_ = profiles.active_for(s, t.tenant, t.name)
    seen = 0
    if app_ is not None:
        for r in s.scalars(select(models.Evidence).where(models.Evidence.kind == "gate", models.Evidence.tenant == t.tenant,
                                                         models.Evidence.created_at >= since).order_by(models.Evidence.seq.desc()).limit(2000)):
            seen += r.body.get("profile") == app_.profile_id
    mcp = []
    for name in t.mcp_servers:
        tgt = s.scalars(select(models.ScanTarget).where(models.ScanTarget.tenant == t.tenant, models.ScanTarget.name == name)).first()
        mcp.append({"name": name, "lastVerdict": tgt.last_verdict if tgt else None, "signed": (tgt.artifact or {}).get("signed") if tgt else None,
                    "refused": bool(tgt and (tgt.artifact or {}).get("signed") is False)})
    return {"id": t.id, "tenant": t.tenant, "name": t.name, "kind": t.kind, "endpoint": t.endpoint, "insertion": t.insertion,
            "modelProvider": t.model_provider, "externalModel": t.external_model, "mcpServers": mcp, "egress": t.egress,
            "application": {"id": app_.id, "profile": app_.profile_id, "stage": app_.stage} if app_ else None,
            "connection": "connected" if seen else ("bound" if app_ else "unbound"), "records24h": seen,
            "modelEgress": _region(s, app_.profile_id if app_ else None).get("modelEgress", "allow"),
            "createdBy": t.created_by, "createdAt": t.created_at.isoformat()}


def targets(s: Session, tenant: str) -> list[dict]:
    return [target_out(s, t) for t in s.scalars(select(models.ProtectedTarget).where(models.ProtectedTarget.tenant == tenant)
                                                 .order_by(models.ProtectedTarget.created_at))]


def save_target(s: Session, tenant: str, body: dict, by: str) -> dict:
    name = str(body.get("name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,119}", name):
        raise InstantError(422, "이름: 영문·숫자·.-_ 2~120자")
    endpoint = str(body.get("endpoint", "")).strip()
    if not ENDPOINT.fullmatch(endpoint):
        raise InstantError(422, "엔드포인트 형식 오류 (MSG-004) — host[:port][/path] 또는 http(s)://…")
    kind, ins = body.get("kind", "other"), body.get("insertion", "gateway")
    if kind not in KINDS or ins not in INSERTIONS:
        raise InstantError(422, f"유형 {KINDS} · 관문 삽입 {INSERTIONS}")
    egress = []
    for e in body.get("egress") or []:
        host = str(e.get("host", "")).strip()
        if not HOST.fullmatch(host):
            raise InstantError(422, f"이그레스 호스트 형식 오류 {host!r} (MSG-004)")
        egress.append({"host": host, "pin": str(e.get("pin") or "")[:100] or None})
    row = s.scalars(select(models.ProtectedTarget).where(models.ProtectedTarget.tenant == tenant, models.ProtectedTarget.name == name)).first()
    ext = bool(body.get("externalModel"))
    app_ = profiles.active_for(s, tenant, name)
    pending = None
    if ext and _region(s, app_.profile_id if app_ else None).get("modelEgress") == "deny" and not (row and row.external_model):
        ext = False                                                    # 정책상 금지 — 승인 후 켠다(MSG-013)
        pending = approvals.create(s, secrets.token_hex(16), tenant, "input", [], f"보호 대상 {name} 외부 모델 호출 허용 (region.modelEgress=deny)", by,
                                   action={"type": "target_external_model", "target": name, "provider": str(body.get("modelProvider", ""))[:200]})
    if row is None:
        row = models.ProtectedTarget(id=f"ptg_{secrets.token_hex(5)}", tenant=tenant, name=name, created_by=by)
        s.add(row)
    row.kind, row.endpoint, row.insertion = kind, endpoint, ins
    row.model_provider = str(body.get("modelProvider") or "self-hosted")[:200]
    row.external_model = ext if pending is None else row.external_model
    row.mcp_servers = [str(x)[:200] for x in body.get("mcpServers") or []][:50]
    row.egress, row.updated_at = egress, utcnow()
    s.flush()
    ledger.append(s, "target", row.id, {"event": "target_saved", "name": name, "kind": kind, "insertion": ins, "externalModel": row.external_model,
                                        "mcpServers": row.mcp_servers, "egress": [e["host"] for e in egress], "by": by}, tenant)
    return target_out(s, row) | ({"approvalRef": pending.id} if pending else {})


def delete_target(s: Session, tenant: str, tid: str, by: str) -> None:
    row = s.get(models.ProtectedTarget, tid)
    if row is None or row.tenant != tenant:
        raise InstantError(404, f"보호 대상 {tid} 없음")
    if profiles.active_for(s, tenant, row.name) is not None:
        raise InstantError(409, "적용된 프로파일이 있다 — 먼저 해제")
    ledger.append(s, "target", tid, {"event": "target_deleted", "name": row.name, "by": by}, tenant)
    s.delete(row)


# ── ① 변경 비교 (SCR-C04) ─────────────────────────────────────
def compare(s: Session, tenant: str, pid: str, target: str | None) -> dict:
    from app import sandbox
    new = profiles.resolve(s, pid)
    cur_app = profiles.active_for(s, tenant, target) if target else None
    cur = profiles.resolve(s, cur_app.profile_id) if cur_app else {"agents": [], "items": []}
    agents = {a.id: a for a in s.scalars(select(models.Agent).where(models.Agent.id.in_(set(new["agents"]) | set(cur["agents"]))))}
    add, rem = sorted(set(new["agents"]) - set(cur["agents"])), sorted(set(cur["agents"]) - set(new["agents"]))
    lat = {g: max((a.latency_budget_ms for i, a in agents.items() if i in new["agents"] and a.gate == g), default=0) for g in ("input", "tool", "output")}
    iso = sorted({agents[i].isolation for i in new["agents"] if i in agents})
    ev_new, ev_cur = _evidence(s, pid), (_evidence(s, cur_app.profile_id) if cur_app else {})
    return {"profile": pid, "target": target, "current": {"id": cur_app.id, "profile": cur_app.profile_id, "stage": cur_app.stage} if cur_app else None,
            "agents": len(new["agents"]), "missing": new["missing"], "added": add, "removed": rem,
            "addedByDomain": {d: sum(agents[i].item_id.startswith(d + "-") or (d == "X" and agents[i].item_id.startswith("X")) for i in add)
                              for d in sorted({agents[i].item_id.split("-")[0] for i in add})},
            "latencyMs": lat, "isolation": iso, "isolationOk": all(sandbox.available(lv) for lv in iso),
            "evidence": {"from": ev_cur, "to": ev_new}, "modelEgress": {"from": _region(s, cur_app.profile_id if cur_app else None).get("modelEgress", "allow"),
                                                                         "to": _region(s, pid).get("modelEgress", "allow")},
            # 코드로 돌려주고 문구는 화면이 언어별로 — evidenceMasked: 원문 masked 보존·열람 2인 승인, modelEgressDeny: 외부 모델 호출은 승인 후
            "approvalNeeded": [x for x in (("evidenceMasked" if ev_new.get("payload") == "masked" else None),
                                           ("modelEgressDeny" if _region(s, pid).get("modelEgress") == "deny" else None)) if x]}


# ── ④ 적용 단계 (SCR-C07) ─────────────────────────────────────
def _domain(item: str) -> str:
    return item.split("-")[0] if item.startswith("D") else "X"


def partial_profile(s: Session, tenant: str, base: str, block_domains: list[str], by: str) -> str:
    """부분 차단 = 선택 도메인만 차단, 나머지 도메인 항목은 경보로 — 테넌트 사용자 정의 프로파일(extends base)."""
    items = profiles.resolve(s, base)["items"]
    keep = set(block_domains)
    overrides = {i: {"verdict": "alert"} for i in items if _domain(i) not in keep}
    pid = f"{base}-p-{'-'.join(sorted(d.lower() for d in keep)) or 'none'}"[:40].rstrip("-")
    raw = {"apiVersion": "aegismesh/v1", "kind": "Profile", "metadata": {"id": pid, "nameKo": f"{base} 부분 차단({', '.join(sorted(keep)) or '없음'})"},
           "spec": {"extends": base, "policyOverrides": overrides, "defaultStage": "enforce", "blocking": f"block {'·'.join(sorted(keep)) or '—'} · alert *"}}
    row, _ = profiles.define(s, raw, tenant, by)
    return row.id


def apply_wizard(s: Session, tenant: str, pid: str, target: str, stage: str, block_domains: list[str] | None, confirmed: bool, by: str) -> dict:
    if not confirmed:
        raise InstantError(422, "강등 정책(fail mode) 확인 필요 (MSG-003)")
    if stage not in profiles.STAGES:
        raise InstantError(422, f"단계 {profiles.STAGES}")
    if s.scalars(select(models.ProtectedTarget).where(models.ProtectedTarget.tenant == tenant, models.ProtectedTarget.name == target)).first() is None:
        raise InstantError(422, f"등록된 보호 대상이 아니다: {target} (② 보호 대상 등록)")
    eff_pid, eff_stage = pid, stage
    if stage == "partial" and block_domains is not None:
        eff_pid, eff_stage = partial_profile(s, tenant, pid, block_domains, by), "enforce"
    if stage == "enforce":
        a = approvals.create(s, secrets.token_hex(16), tenant, "input", [], f"{target} 에 {pid} 전체 차단 적용", by, required=1,
                             action={"type": "profile_apply", "profile": eff_pid, "target": target, "stage": "enforce"})
        return {"approvalRef": a.id, "status": "pending", "profile": eff_pid, "stage": "enforce", "note": "전체 차단은 승인자 승인 후 적용"}
    row = profiles.apply(s, eff_pid, tenant, target, eff_stage, by)
    return {"application": row.id, "profile": eff_pid, "stage": eff_stage, "agents": len(row.agent_ids), "blockDomains": block_domains}


def rollback(s: Session, tenant: str, target: str, by: str) -> dict:
    """프로파일 해제 = 이전 스냅샷 복귀 — 현재 적용을 내리고 같은 대상의 직전 적용을 다시 켠다(없으면 미적용)."""
    cur = profiles.active_for(s, tenant, target)
    if cur is None:
        raise InstantError(409, f"{target} 에 적용된 프로파일 없음")
    prev = s.scalars(select(models.ProfileApplication).where(models.ProfileApplication.tenant == tenant, models.ProfileApplication.target == target,
                                                            models.ProfileApplication.id != cur.id, models.ProfileApplication.applied_at <= cur.applied_at)
                     .order_by(models.ProfileApplication.applied_at.desc()).limit(1)).first()
    profiles.release(s, cur.id, by)
    if prev is not None:
        s.execute(update(models.ProfileApplication).where(models.ProfileApplication.id == prev.id).values(active=True))
        ledger.append(s, "profile", prev.id, {"event": "profile_restored", "from": cur.id, "profile": prev.profile_id, "target": target, "by": by}, tenant)
    return {"released": cur.id, "restored": {"id": prev.id, "profile": prev.profile_id, "stage": prev.stage} if prev else None}


def apply_action(s: Session, row: models.Approval) -> dict:
    act = row.action or {}
    if act["type"] == "profile_apply":
        app_ = profiles.apply(s, act["profile"], row.tenant, act["target"], act["stage"], f"approval:{row.id}")
        return {"applied": "profile_apply", "application": app_.id, "profile": act["profile"], "target": act["target"]}
    t = s.scalars(select(models.ProtectedTarget).where(models.ProtectedTarget.tenant == row.tenant, models.ProtectedTarget.name == act["target"])).first()
    if t is not None:
        t.external_model, t.model_provider, t.updated_at = True, act.get("provider") or t.model_provider, utcnow()
    return {"applied": "target_external_model", "target": act["target"]}
