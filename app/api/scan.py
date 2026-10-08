"""상시 점검 API — 즉시 점검, 점검 대상 등록, 격리 목록 (C3, PRD §8.2)."""
import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger, models, scanner
from app.api.deps import (
    Ctx,
    ctx,
    need,
    read_tenant,
    session,
    visible_or_404,
    write_tenant,
)

router = APIRouter(prefix="/v1", tags=["scan"], dependencies=[Depends(ctx)])


class ScanIn(BaseModel):
    artifact: dict
    tenant: str | None = None
    agents: list[str] | None = None


@router.post("/scan")
def scan(body: ScanIn, s: Session = Depends(session), c: Ctx = Depends(need("scan"))):
    tenant = write_tenant(s, c, body.tenant)
    if not body.artifact.get("kind"):
        raise HTTPException(422, "artifact.kind 필요")
    r = scanner.run_scan(s, body.artifact, tenant, agent_ids=body.agents, by=c.name)
    s.commit()
    return r


class TargetIn(BaseModel):
    name: str = Field(min_length=1)
    artifact: dict
    tenant: str | None = None
    intervalSec: int = Field(3600, ge=10)


def target_out(t: models.ScanTarget) -> dict:
    return {"id": t.id, "tenant": t.tenant, "kind": t.kind, "name": t.name, "intervalSec": t.interval_sec,
            "enabled": t.enabled, "lastRunAt": t.last_run_at.isoformat() if t.last_run_at else None,
            "lastVerdict": t.last_verdict}


@router.get("/scan-targets")
def list_targets(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    q = select(models.ScanTarget).order_by(models.ScanTarget.created_at)
    if t := read_tenant(c, tenant):
        q = q.where(models.ScanTarget.tenant == t)
    return {"items": [target_out(x) for x in s.scalars(q)]}


@router.post("/scan-targets", status_code=201)
def add_target(body: TargetIn, s: Session = Depends(session), c: Ctx = Depends(need("scan"))):
    who, tenant = c.name, write_tenant(s, c, body.tenant)
    kind = body.artifact.get("kind")
    if not kind:
        raise HTTPException(422, "artifact.kind 필요")
    t = models.ScanTarget(id=f"tgt_{secrets.token_hex(6)}", tenant=tenant, kind=kind, name=body.name,
                          artifact={**body.artifact, "name": body.artifact.get("name", body.name)},
                          interval_sec=body.intervalSec)
    s.add(t)
    s.flush()
    ledger.append(s, "scan", t.id, {"event": "target_registered", "kind": kind, "name": body.name, "by": who}, tenant)
    s.commit()
    return target_out(t)


@router.post("/scan-targets/{tid}:run")
def run_target(tid: str, s: Session = Depends(session), c: Ctx = Depends(need("scan"))):
    t = s.get(models.ScanTarget, tid)
    visible_or_404(c, t, f"scan target {tid}")
    r = scanner.run_scan(s, t.artifact, t.tenant, t, by=c.name)
    s.commit()
    return r


def quarantine_out(q: models.Quarantine) -> dict:
    exp = q.expires_at.replace(tzinfo=q.expires_at.tzinfo or UTC) if q.expires_at else None
    return {"id": q.id, "tenant": q.tenant, "kind": q.kind, "value": q.value, "reason": q.reason, "findingIds": q.finding_ids,
            "active": q.active, "createdAt": q.created_at.isoformat(), "releasedBy": q.released_by,
            "expiresAt": exp.isoformat() if exp else None, "expired": bool(exp and exp <= datetime.now(UTC))}


@router.get("/quarantine")
def list_quarantine(active: bool = True, tenant: str | None = None, s: Session = Depends(session),
                    c: Ctx = Depends(need("read"))):
    q = select(models.Quarantine).order_by(models.Quarantine.created_at.desc())
    if t := read_tenant(c, tenant):
        q = q.where(models.Quarantine.tenant == t)
    if active:
        q = q.where(models.Quarantine.active.is_(True))
    return {"items": [quarantine_out(x) for x in s.scalars(q)]}


@router.post("/quarantine/{qid}:release")
def release_quarantine(qid: str, s: Session = Depends(session), c: Ctx = Depends(need("scan"))):
    q = s.get(models.Quarantine, qid)
    visible_or_404(c, q, f"quarantine {qid}")
    if q.kind in ("principal", "session") and q.active:            # 깊은 검사 격리(Epic 51) — 해제는 2인 승인
        from app import approvals
        a = approvals.create(s, secrets.token_hex(16), q.tenant, "input", list(q.finding_ids or []),
                             f"{q.kind} {q.value} — 격리 해제 요청: {c.name}", c.name,
                             action={"type": "quarantine_release", "kind": q.kind, "name": q.value, "decision": "release",
                                     "reason": f"{c.name} 해제 요청"})
        s.commit()
        return JSONResponse({"approvalRef": a.id, "status": a.status, "required": a.required}, status_code=202)
    try:
        q = scanner.release(s, qid, c.name)
    except KeyError:
        raise HTTPException(404, f"quarantine {qid} 없음") from None
    s.commit()
    return quarantine_out(q)
