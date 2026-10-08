"""증적 보존기한 만료 배치 (원본 PRD NFR-S · R07 · COMPLIANCE 추가 시험 '감사로그 보관기간 경과 삭제 증명').

원장은 추가 전용이고 삭제 API 가 없다. 보존기한이 지난 앞부분만 **2인 승인 배치**로 지운다.
- 경계 = 서명 체크포인트(seq·해시·서명이 남아 있는 지점) 중 기한이 지났고 **법적 보존 기록보다 앞선** 가장 큰 것.
- 지우기 전에 서명 삭제 증명서(체인·구간·건수·기준일·앵커 해시·체크포인트 서명·승인자)를 `ledger_purges` 에 넣는다.
  DB 트리거는 이 행이 덮는 구간의 DELETE 만 허용한다. 같은 체인에 `retention_purged` 기록을 이어 붙여 증명이 체인 안에도 남는다.
- 검증은 마지막 앵커 해시에서 다시 시작하고, 증명서 서명과 앵커 = 체크포인트 해시를 확인한다(구간 밖 변조는 그대로 잡힌다).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from aegis.ledger_verify import verify_signature
from aegis.schemas import now_iso
from app import approvals, db, ledger, models
from app.core.config import settings


class RetentionError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def days_for(s: Session, chain: str) -> int:
    t = s.get(models.Tenant, chain)
    return t.retention_days if t is not None else settings.evidence_retention_days


def last_purge(s: Session, chain: str) -> models.LedgerPurge | None:
    return s.scalars(select(models.LedgerPurge).where(models.LedgerPurge.chain == chain).order_by(models.LedgerPurge.through_seq.desc())).first()


def holds(s: Session, chain: str) -> dict:
    """법적 보존 — 포렌식 보존 기록 자체와 그 묶음이 가리키는 기록(seq)·판정 기록. 가장 앞선 seq 앞에서 멈춘다."""
    E = models.Evidence
    seqs, incidents = [], []
    for r in s.scalars(select(E).where(E.chain == chain, E.kind == "forensic")):
        incidents.append(r.ref_id)
        seqs.append(r.seq)
        b = r.body.get("bundle") or {}
        seqs += [x["seq"] for x in b.get("records", []) if isinstance(x.get("seq"), int)]
        fids = [f["id"] for f in b.get("findings", []) if f.get("id")]
        if fids:
            m = s.scalar(select(func.min(E.seq)).where(E.chain == chain, E.kind == "finding", E.ref_id.in_(fids[:500])))
            if m:
                seqs.append(m)
    return {"minSeq": min(seqs) if seqs else None, "incidents": sorted(set(incidents))}


def plan(s: Session, chain: str, now: datetime | None = None) -> dict:
    if chain == ledger.LEGACY:
        return {"chain": chain, "eligible": False, "reason": "legacy 체인은 동결 — 대상 아님"}
    now = now or _now()
    days = days_for(s, chain)
    cutoff = _iso(now - timedelta(days=days))
    lp = last_purge(s, chain)
    start = lp.through_seq if lp else 0
    hold = holds(s, chain)
    E, C = models.Evidence, models.LedgerCheckpoint
    q = select(C).join(E, (E.seq == C.seq) & (E.chain == C.chain)).where(C.chain == chain, C.seq > start, E.created_at < cutoff)
    if hold["minSeq"] is not None:
        q = q.where(C.seq < hold["minSeq"])
    cp = s.scalars(q.order_by(C.seq.desc()).limit(1)).first()
    total = s.scalar(select(func.count()).select_from(E).where(E.chain == chain)) or 0
    out = {"chain": chain, "retentionDays": days, "cutoff": cutoff, "records": total, "lastPurge": purge_out(lp) if lp else None,
           "legalHold": hold, "eligible": False}
    if cp is None:
        return out | {"reason": "기한 지난 서명 체크포인트 없음" if hold["minSeq"] is None else "법적 보존 기록 앞에 기한 지난 체크포인트 없음"}
    n = s.scalar(select(func.count()).select_from(E).where(E.chain == chain, E.seq > start, E.seq <= cp.seq)) or 0
    first = s.scalar(select(func.min(E.seq)).where(E.chain == chain, E.seq > start))
    return out | {"eligible": n > 0, "throughSeq": cp.seq, "fromSeq": first, "purge": n, "anchorHash": cp.hash}


def request(s: Session, chain: str, by: str) -> dict:
    p = plan(s, chain)
    if not p.get("eligible"):
        raise RetentionError(409, f"만료 대상 없음 — {p.get('reason', '')}")
    pend = [a for a in s.scalars(select(models.Approval).where(models.Approval.status == "pending"))
            if (a.action or {}).get("type") == "evidence_purge" and a.action.get("chain") == chain]
    if pend:
        raise RetentionError(409, f"이미 승인 대기 — {pend[0].id}")
    tenant = chain if s.get(models.Tenant, chain) else "default"
    a = approvals.create(s, secrets.token_hex(16), tenant, "offline", [], f"증적 보존기한 만료 삭제 — {chain} seq {p['fromSeq']}~{p['throughSeq']} "
                         f"({p['purge']}건, {p['retentionDays']}일 경과)", by, required=2,
                         action={"type": "evidence_purge", "chain": chain, "throughSeq": p["throughSeq"], "cutoff": p["cutoff"], "purge": p["purge"]})
    ledger.append(s, "retention", chain, {"event": "retention_requested", "plan": {k: p[k] for k in ("fromSeq", "throughSeq", "purge", "cutoff", "retentionDays")},
                                          "approval": a.id, "by": by}, chain)
    return {"approvalRef": a.id, "plan": p}


def _sign(cert: dict) -> str:
    msg = json.dumps(cert, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.b64encode(ledger.signing_key().sign(msg)).decode()


def apply(s: Session, row: models.Approval) -> dict:
    """승인 완료 → 다시 계산한 계획이 승인 범위를 넘지 않을 때만 실행. 증명서 → 삭제 → 체인에 결과 기록."""
    act = row.action or {}
    chain = act["chain"]
    db.set_scope(s, "*")                                                # 시스템 배치 — 체인 전체 대상
    p = plan(s, chain)
    # 승인 범위 ∩ 지금 계획 — 그사이 법적 보존이 생겼으면 더 앞(작은 체크포인트)까지만. 둘 다 서명 체크포인트다.
    through = min(act["throughSeq"], p["throughSeq"]) if p.get("eligible") else None
    if not through:
        ledger.append(s, "retention", chain, {"event": "retention_skipped", "reason": p.get("reason"), "approval": row.id}, chain)
        return {"applied": "evidence_purge", "chain": chain, "purged": 0, "reason": p.get("reason")}
    cp = s.get(models.LedgerCheckpoint, through)
    E = models.Evidence
    lp = last_purge(s, chain)
    start = lp.through_seq if lp else 0
    n = s.scalar(select(func.count()).select_from(E).where(E.chain == chain, E.seq > start, E.seq <= through)) or 0
    first = s.scalar(select(func.min(E.seq)).where(E.chain == chain, E.seq > start)) or start + 1     # 전역 seq — 체인 안 첫 기록
    decided = s.scalars(select(models.ApprovalDecision).where(models.ApprovalDecision.approval_id == row.id)).all()
    cert = {"format": "aegismesh.retention/v1", "chain": chain, "fromSeq": first, "throughSeq": through, "records": n,
            "anchorHash": cp.hash, "checkpoint": {"seq": cp.seq, "hash": cp.hash, "signature": cp.signature, "keyId": cp.key_id},
            "previousAnchor": lp.anchor_hash if lp else None, "cutoff": p["cutoff"], "retentionDays": p["retentionDays"],
            "legalHold": p["legalHold"], "approval": row.id, "requestedBy": row.requested_by,
            "approvers": [d.principal for d in decided if d.decision == "approve"], "purgedAt": now_iso(), "keyId": ledger.key_id()}
    purge = models.LedgerPurge(id=f"prg_{secrets.token_hex(6)}", chain=chain, through_seq=through, anchor_hash=cp.hash, records=n,
                               certificate=cert, signature=_sign(cert), key_id=ledger.key_id(), created_at=cert["purgedAt"])
    s.add(purge)
    s.flush()                                                           # 트리거가 볼 수 있게 먼저
    deleted = s.execute(delete(E).where(E.chain == chain, E.seq > start, E.seq <= through)).rowcount or 0
    digest = hashlib.sha256(json.dumps(cert, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    ledger.append(s, "retention", chain, {"event": "retention_purged", "purge": purge.id, "fromSeq": first, "throughSeq": through,
                                          "records": deleted, "anchorHash": cp.hash, "certificateSha256": digest, "approval": row.id}, chain)
    return {"applied": "evidence_purge", "chain": chain, "purge": purge.id, "purged": deleted, "throughSeq": through}


def purge_out(r: models.LedgerPurge) -> dict:
    return {"id": r.id, "chain": r.chain, "throughSeq": r.through_seq, "records": r.records, "anchorHash": r.anchor_hash,
            "createdAt": r.created_at, "certificate": r.certificate, "signature": r.signature, "keyId": r.key_id,
            "signatureOk": verify_cert(r)}


def verify_cert(r: models.LedgerPurge) -> bool:
    pub = base64.b64encode(ledger.public_raw()).decode()
    msg = json.dumps(r.certificate, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(r.signature), msg)
    except Exception:  # noqa: BLE001 — 서명 불일치·형식 오류 = 실패
        return False
    cp = r.certificate.get("checkpoint") or {}
    return r.certificate.get("anchorHash") == r.anchor_hash == cp.get("hash") and verify_signature(pub, cp)


def overview(s: Session, chains: list[str]) -> dict:
    return {"items": [plan(s, c) for c in chains],
            "purges": [purge_out(r) for r in s.scalars(select(models.LedgerPurge).where(models.LedgerPurge.chain.in_(chains))
                                                        .order_by(models.LedgerPurge.created_at.desc()).limit(50))]}


def due_requests(s: Session) -> list[dict]:
    """worker — 만료 대상이 있고 대기 중 요청이 없는 체인마다 2인 승인 요청을 낸다(실행은 승인 뒤)."""
    out = []
    for c in ledger.chains(s):
        try:
            out.append(request(s, c, "worker") | {"chain": c})
        except RetentionError:
            continue
    return out
