"""판정 저장 — Finding 을 조회용 테이블과 증적 원장에 함께 남긴다. 원문·무해화 결과는 저장하지 않는다(NFR-D1)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from aegis.schemas import Finding
from app import ledger, models


def sanitized(f: Finding) -> dict:
    body = f.dump()
    body["action"]["transformApplied"] = body["action"].pop("transform") is not None
    return body


def row(f: Finding, effective: str | None = None) -> models.Finding:
    body = sanitized(f) | ({"effectiveVerdict": effective} if effective else {})
    return models.Finding(id=f.id, trace_id=f.trace_id, tenant=f.subject.tenant, agent_id=f.agent.id, gate=f.gate,
                          verdict=f.verdict, severity=f.severity, confidence=f.confidence, rule_id=f.rule_id,
                          valid=f.valid, degraded=f.degraded, body=body,
                          occurred_at=datetime.fromisoformat(f.occurred_at.replace("Z", "+00:00")))


def store(s: Session, f: Finding, effective: str | None = None) -> models.Finding:
    r = row(f, effective)
    s.add(r)
    ledger.append(s, "finding", f.id, r.body, f.subject.tenant)
    return r
