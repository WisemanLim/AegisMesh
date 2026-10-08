"""원장 저장 재암호화 (Epic 57 · NFR-D2) — 저장 암호화(Epic 49) 전에 쌓인 원장 기록을 봉투 암호화로 바꾼다. 원장은 추가 전용 그대로:

- 요청 → 2인 승인 → 서명 증명서가 붙은 재암호화 창(ledger_rewraps: seq 구간·만료) → 묶음 재암호화(worker 주기 또는 `make ledger-rewrap`).
- DB 트리거(0022)는 창 안에서 '평문 → 봉투 암호문, 다른 열 불변' 갱신만 허용한다. 내용이 같은지는 해시 체인(평문 기준 해시)이 보증 —
  다른 값을 암호화해 넣으면 원장 검증이 깨진다. 끝나면 원장에 결과(건수·시간·KEK).
- 실행 중 표·덤프에는 평문이 남지 않는다. 옛 기본 백업·보관 WAL·외부 복사본의 평문은 보존 주기(DB_BACKUP_KEEP)로 사라진다.
  PostgreSQL 은 갱신 전 행 판이 페이지에 남으므로 `make ledger-rewrap ENV=prod VACUUM=1`(VACUUM FULL) 로 파일을 다시 쓴다.

  python -m app.ledger_rewrap status | run
"""
from __future__ import annotations

import base64
import json
import secrets
import sys
import time
from datetime import datetime, timezone

from sqlalchemy import bindparam, func, select, text, update
from sqlalchemy.orm import Session

from app import approvals, db, kms, ledger, models
from app.core.config import settings
from app.ledger import now_iso

ENC = '{"_enc"%'                                                        # EncryptedJSON 이 쓰는 저장 형식의 앞부분


class RewrapError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _sign(cert: dict) -> str:
    msg = json.dumps(cert, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.b64encode(ledger.signing_key().sign(msg)).decode()


def verify_cert(w: models.LedgerRewrap) -> bool:
    try:
        ledger.signing_key().public_key().verify(base64.b64decode(w.signature),
                                                 json.dumps(w.certificate, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
        return True
    except Exception:  # noqa: BLE001 — 서명 형식 오류도 '검증 실패'
        return False


def _kek() -> str:
    return kms.kek_of(kms.seal(b"probe", "probe"))


def plan(s: Session) -> dict:
    """평문 원장 기록 수·seq 구간(저장 형식 앞부분으로 판별 — JSON 을 풀지 않아 빠르다)."""
    n, lo, hi = s.execute(text("SELECT count(*), min(seq), max(seq) FROM evidence WHERE CAST(body AS TEXT) NOT LIKE :p"), {"p": ENC}).one()
    return {"plaintext": n or 0, "fromSeq": lo, "throughSeq": hi, "records": s.scalar(select(func.count()).select_from(models.Evidence)) or 0}


def active(s: Session) -> models.LedgerRewrap | None:
    return s.scalars(select(models.LedgerRewrap).where(models.LedgerRewrap.expires_epoch > int(time.time()))
                     .order_by(models.LedgerRewrap.created_at.desc())).first()


def _out(w: models.LedgerRewrap) -> dict:
    return {"id": w.id, "fromSeq": w.from_seq, "throughSeq": w.through_seq, "records": w.records, "createdAt": w.created_at,
            "expiresAt": datetime.fromtimestamp(w.expires_epoch, timezone.utc).isoformat(timespec="seconds"),
            "active": w.expires_epoch > time.time(), "certificate": w.certificate, "signatureOk": verify_cert(w)}


def overview(s: Session) -> dict:
    ws = list(s.scalars(select(models.LedgerRewrap).order_by(models.LedgerRewrap.created_at.desc()).limit(20)))
    pend = [a.id for a in s.scalars(select(models.Approval).where(models.Approval.status == "pending"))
            if (a.action or {}).get("type") == "ledger_rewrap"]
    return plan(s) | {"windows": [_out(w) for w in ws], "pendingApproval": pend[0] if pend else None, "kek": _kek(),
                      "windowSec": settings.ledger_rewrap_window_sec}


def request(s: Session, by: str) -> dict:
    db.set_scope(s, "*")                                                # 원장 전체(모든 체인) — 플랫폼 작업
    p = plan(s)
    if not p["plaintext"]:
        raise RewrapError(409, "평문 원장 기록 없음 — 이미 모두 암호화됨")
    if overview(s)["pendingApproval"]:
        raise RewrapError(409, "이미 승인 대기 중인 재암호화 요청이 있다")
    a = approvals.create(s, secrets.token_hex(16), "default", "offline", [],
                         f"원장 저장 재암호화 — seq {p['fromSeq']}~{p['throughSeq']} 평문 {p['plaintext']}건(내용·해시 불변, 창 {settings.ledger_rewrap_window_sec // 3600}시간)",
                         by, required=2, action={"type": "ledger_rewrap", "fromSeq": p["fromSeq"], "throughSeq": p["throughSeq"],
                                                  "plaintext": p["plaintext"]})
    ledger.append(s, "kms", "ledger", {"event": "ledger_rewrap_requested", "plan": p, "approval": a.id, "by": by})
    return {"approvalRef": a.id, "plan": p}


def apply(s: Session, row: models.Approval) -> dict:
    """승인 완료 → 서명 증명서와 함께 재암호화 창을 연다(실행은 worker·CLI 가 묶음으로)."""
    act = row.action or {}
    db.set_scope(s, "*")
    decided = s.scalars(select(models.ApprovalDecision).where(models.ApprovalDecision.approval_id == row.id)).all()
    expires = int(time.time()) + settings.ledger_rewrap_window_sec
    cert = {"format": "aegismesh.ledger-rewrap/v1", "fromSeq": act["fromSeq"], "throughSeq": act["throughSeq"], "plaintext": act["plaintext"],
            "kek": _kek(), "approval": row.id, "requestedBy": row.requested_by,
            "approvers": [d.principal for d in decided if d.decision == "approve"], "openedAt": now_iso(),
            "expiresAt": datetime.fromtimestamp(expires, timezone.utc).isoformat(timespec="seconds"), "keyId": ledger.key_id()}
    w = models.LedgerRewrap(id=f"rwp_{secrets.token_hex(6)}", from_seq=act["fromSeq"], through_seq=act["throughSeq"], expires_epoch=expires,
                            records=act["plaintext"], certificate=cert, signature=_sign(cert), key_id=ledger.key_id(), created_at=cert["openedAt"])
    s.add(w)
    s.flush()
    ledger.append(s, "kms", "ledger", {"event": "ledger_rewrap_opened", "window": w.id, "fromSeq": w.from_seq, "throughSeq": w.through_seq,
                                       "plaintext": w.records, "expiresAt": cert["expiresAt"], "approval": row.id})
    return {"applied": "ledger_rewrap", "window": w.id, "expiresAt": cert["expiresAt"]}


def run(s: Session, budget_sec: float | None = None) -> dict:
    """열린 창 안의 평문 기록을 묶음마다 다시 쓰며 암호화(묶음마다 커밋). 다 끝나면 원장에 결과 1건."""
    db.set_scope(s, "*")
    w = active(s)
    if w is None:
        return {"window": None}
    t = models.Evidence.__table__
    stmt = update(t).where(t.c.seq == bindparam("_seq")).values(body=bindparam("_b", type_=t.c.body.type))
    lock = " FOR UPDATE SKIP LOCKED" if s.get_bind().dialect.name == "postgresql" else ""   # worker·CLI 가 함께 돌아도 같은 행을 두 번 쓰지 않게
    q = text("SELECT seq, body FROM evidence WHERE seq BETWEEN :a AND :b AND seq > :last AND CAST(body AS TEXT) NOT LIKE :p ORDER BY seq LIMIT :n" + lock)
    t0, last, done = time.time(), w.from_seq - 1, 0
    while w.expires_epoch > time.time() and (budget_sec is None or time.time() - t0 < budget_sec):
        rows = s.execute(q, {"a": w.from_seq, "b": w.through_seq, "last": last, "p": ENC, "n": settings.ledger_rewrap_batch}).all()
        if not rows:
            break
        s.execute(stmt, [{"_seq": r[0], "_b": kms._raw(r[1])} for r in rows])   # 열 타입이 현재 DEK 로 봉투 암호화
        s.commit()
        db.set_scope(s, "*")
        last, done = rows[-1][0], done + len(rows)
    left = s.execute(text("SELECT count(*) FROM evidence WHERE seq BETWEEN :a AND :b AND CAST(body AS TEXT) NOT LIKE :p"),
                     {"a": w.from_seq, "b": w.through_seq, "p": ENC}).scalar() or 0
    out = {"window": w.id, "rewrapped": done, "remaining": left, "sec": round(time.time() - t0, 1), "kek": _kek()}
    if not left and s.scalar(select(func.count()).select_from(models.Evidence).where(models.Evidence.ref_id == w.id)) == 0:
        ledger.append(s, "kms", w.id, {"event": "ledger_rewrapped", "window": w.id, "fromSeq": w.from_seq, "throughSeq": w.through_seq,
                                       "records": w.records, "kek": out["kek"], "lastRunSec": out["sec"]})
        s.commit()
        out["completed"] = True
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    with db.system_session() as s:
        db.set_scope(s, "*")
        if cmd == "status":
            r = overview(s)
            r["windows"] = [{k: v for k, v in x.items() if k != "certificate"} for x in r["windows"]]
        elif cmd == "run":
            r = run(s)
        else:
            raise SystemExit(__doc__)
    print(json.dumps(r, ensure_ascii=False, default=str))
