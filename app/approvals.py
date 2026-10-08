"""사람 승인 (require_approval) — 2인 승인, 본인 요청 승인 금지, 사유 필수 (UI CMP-10, MSG-011)."""
from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger, models
from app.core.config import settings
from app.models import utcnow


class ApprovalError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def create(s: Session, trace_id: str, tenant: str, gate: str, finding_ids: list[str], summary: str,
           requested_by: str, required: int = 2, action: dict | None = None, records: list | None = None) -> models.Approval:
    """action 이 있으면 승인 완료 시 실행된다(정책 롤백 등 — 승인 없이는 바뀌지 않는다).
    records 를 주면 원장 기록을 거기에 모은다(인라인 판정의 비동기 적재)."""
    row = models.Approval(id=f"apr_{secrets.token_hex(6)}", trace_id=trace_id, tenant=tenant, gate=gate,
                          finding_ids=finding_ids, summary=summary, requested_by=requested_by, required=required,
                          action=action, expires_at=utcnow() + timedelta(minutes=settings.approval_ttl_min))
    s.add(row)
    s.flush()
    rec = ("approval", row.id, {"event": "requested", "traceId": trace_id, "gate": gate, "findings": finding_ids,
                                "requestedBy": requested_by, "required": required, "action": action})
    if records is None:
        ledger.append(s, *rec, tenant)
    else:
        records.append(rec)
    return row


def _utc(dt):
    from datetime import timezone
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def expire(s: Session, row: models.Approval, by: str) -> None:
    """만료 = 자동 거절 — 행동은 실행되지 않는다. 원장에 남긴다."""
    row.status, row.decided_at = "expired", utcnow()
    ledger.append(s, "approval", row.id, {"event": "expired", "by": by, "expiresAt": _utc(row.expires_at).isoformat()}, row.tenant)


def expire_due(s: Session, by: str = "worker") -> int:
    rows = list(s.scalars(select(models.Approval).where(models.Approval.status == "pending", models.Approval.expires_at.is_not(None),
                                                        models.Approval.expires_at <= utcnow())))
    for r in rows:
        expire(s, r, by)
    return len(rows)


def decide(s: Session, approval_id: str, principal: str, decision: str, reason: str) -> models.Approval:
    row = s.get(models.Approval, approval_id)
    if not row:
        raise ApprovalError(404, f"승인 요청 {approval_id} 없음")
    if decision not in ("approve", "reject"):
        raise ApprovalError(422, "decision 은 approve|reject")
    if not reason or not reason.strip():
        raise ApprovalError(422, "사유 입력 필수")
    if principal in ("", "anonymous"):
        raise ApprovalError(401, "승인 주체 필요")
    if row.status == "pending" and row.expires_at is not None and _utc(row.expires_at) <= utcnow():
        expire(s, row, "decide")
        s.commit()                                     # 자동 거절은 오류 응답과 함께 남긴다(롤백되지 않게)
        raise ApprovalError(409, "만료된 요청 — 자동 거절됨 (SCR-O06)")
    if row.status != "pending":
        raise ApprovalError(409, f"이미 종결된 요청 ({row.status})")
    if principal == row.requested_by:
        raise ApprovalError(403, "본인이 요청한 행동은 승인할 수 없다 (MSG-011)")
    prior = s.scalars(select(models.ApprovalDecision).where(models.ApprovalDecision.approval_id == row.id)).all()
    if any(d.principal == principal for d in prior):
        raise ApprovalError(409, "같은 승인자가 두 번 결정할 수 없다 (2인 승인)")
    s.add(models.ApprovalDecision(approval_id=row.id, principal=principal, decision=decision, reason=reason))
    approvals = sum(d.decision == "approve" for d in prior) + (decision == "approve")
    if decision == "reject":
        row.status, row.decided_at = "rejected", utcnow()
    elif approvals >= row.required:
        row.status, row.decided_at = "approved", utcnow()
    ledger.append(s, "approval", row.id, {"event": "decided", "by": principal, "decision": decision,
                                           "reason": reason, "status": row.status,
                                           "approvals": approvals, "required": row.required}, row.tenant)
    if row.status == "approved" and row.action:
        result = _dispatch(s, row)
        ledger.append(s, "approval", row.id, {"event": "action_applied", **result}, row.tenant)
    return row


def _dispatch(s: Session, row: models.Approval) -> dict:
    """승인 연계 행동 — 정책 롤백(SCR-D03) · 관문 재배치(SCR-D02) · 신뢰 저장소 키 추가·폐기(SCR-R05) · 장터 설치(SCR-C10)."""
    kind = row.action["type"]
    if kind in ("policy_rollback", "gate_relocate", "gate_restore"):
        from app import policy
        return policy.apply_action(s, row)
    if kind in ("trust_key_add", "trust_key_revoke"):
        from app import airgap
        return airgap.apply_action(s, row)
    if kind == "market_install":
        from app import market
        return market.apply_action(s, row)
    if kind in ("supply_decision", "quarantine_release"):                 # SCR-K02~K04·M03 공급망·격리 2인 결정
        from app import domains
        return domains.apply_supply(s, row)
    if kind == "runbook_step":                                          # SCR-O07 런북 단계(신원 회전) 2인 승인
        from app import workflow
        return workflow.apply_runbook(s, row)
    if kind in ("profile_apply", "target_external_model"):              # SCR-C07 전체 차단 적용 · C05 외부 모델 허용
        from app import instant
        return instant.apply_action(s, row)
    if kind == "agent_promote":                                         # OQ2 — 격리 미달 등록 에이전트 차단 승격(2인)
        a = s.get(models.Agent, row.action["agent"])
        if a is None or a.status != "alert_only":
            return {"applied": "agent_promote", "agent": row.action["agent"], "skipped": "상태 변경됨"}
        a.status = "active"
        from app import registry
        registry.runtime_agent.cache_clear()
        ledger.append(s, "agent", a.id, {"event": "promoted", "approval": row.id, "from": "alert_only", "to": "active"})
        return {"applied": "agent_promote", "agent": a.id, "status": "active"}
    if kind == "evidence_purge":                                        # 증적 보존기한 만료 삭제(2인, NFR-S)
        from app import retention
        return retention.apply(s, row)
    if kind == "ledger_rewrap":                                         # 원장 저장 재암호화 창(2인, Epic 57 NFR-D2)
        from app import ledger_rewrap
        return ledger_rewrap.apply(s, row)
    if kind == "sample_retention":                                      # OQ1 미리보기 표본 보존 켜기·확대(2인)
        from app import samples
        return samples.apply_action(s, row)
    if kind == "card_publish":                                          # SCR-N07 카드 공개(검토 → 승인)
        from app import compliance
        return compliance.apply_publish(s, row)
    if kind == "redteam_run":
        from app import console
        return console.apply_redteam(s, row)
    raise ValueError(f"알 수 없는 승인 행동 {kind}")


def out(s: Session, row: models.Approval) -> dict:
    ds = s.scalars(select(models.ApprovalDecision).where(models.ApprovalDecision.approval_id == row.id)
                   .order_by(models.ApprovalDecision.at)).all()
    return {"id": row.id, "traceId": row.trace_id, "tenant": row.tenant, "gate": row.gate,
            "findingIds": row.finding_ids, "summary": row.summary, "requestedBy": row.requested_by,
            "required": row.required, "status": row.status, "createdAt": row.created_at.isoformat(), "action": row.action,
            "expiresAt": _utc(row.expires_at).isoformat() if row.expires_at else None,
            "decidedAt": row.decided_at.isoformat() if row.decided_at else None,
            "decisions": [{"principal": d.principal, "decision": d.decision, "reason": d.reason,
                           "at": d.at.isoformat()} for d in ds]}
