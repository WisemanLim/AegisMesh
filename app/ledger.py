"""증적 원장 (FR-P05, DP9) — 추가 전용 해시 체인 + 서명 체크포인트 + 서명 묶음 내보내기.

저장소는 RDB 테이블(evidence). 대용량(NFR-P3) 단계에서 열 지향 DB 로 교체할 수 있도록
append / records / verify / export 네 함수만 외부에 노출한다.
"""
from __future__ import annotations

import base64
import secrets
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from aegis.ledger_verify import (
    BUNDLE_FORMAT,
    GENESIS,
    checkpoint_message,
    key_id_of,
    record_hash,
    verify_signature,
)
from aegis.schemas import now_iso
from app import kms, models
from app.core.config import settings


# ── 서명 키 ────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def signing_key() -> Ed25519PrivateKey:
    """LEDGER_SIGNING_KEY(base64 32바이트) 우선. 없으면 데이터 디렉터리에 생성·보관(로컬·리허설용).
    운영은 외부 키 관리 시스템에서 주입한다(NFR-D2)."""
    raw = settings.ledger_signing_key
    if raw and raw != "CHANGE_ME":
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
    return Ed25519PrivateKey.from_private_bytes(kms.secret_file(Path(settings.ledger_key_file), _new_ed25519))   # KMS 포장 저장(NFR-D2)


def _new_ed25519() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                     serialization.NoEncryption())


def public_raw() -> bytes:
    return signing_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id() -> str:
    return key_id_of(public_raw())


# ── 적재 ──────────────────────────────────────────────────────
LEGACY = "legacy"          # 0006 이전 단일 체인 (동결 — 검증만)
PLATFORM = "platform"      # 테넌트에 속하지 않는 플랫폼 사건(에이전트 등록·게시자·거버넌스·레드팀 등)


def ensure_chain(s: Session, chain: str) -> models.LedgerChain:
    head = s.get(models.LedgerChain, chain)
    if head is None:
        head = models.LedgerChain(chain=chain, seq=0, hash=GENESIS, count=0)
        s.add(head)
        s.flush()
    return head


def append(s: Session, kind: str, ref_id: str, body: dict, tenant: str = PLATFORM) -> models.Evidence:
    """테넌트 체인 머리를 잠그고 한 건 적재 (체인 = 테넌트, FR-P13 증적 파티션). 호출자가 commit 한다.

    SQLite 는 SELECT … FOR UPDATE 를 무시하므로, 머리 행에 무변경 UPDATE 를 먼저 보내 쓰기 잠금을 선점한다
    (SQLite: 데이터베이스 RESERVED 잠금, PostgreSQL·MySQL: 행 잠금). 동시 적재가 같은 prev_hash 를 읽어
    체인이 갈라지는 것을 막는다."""
    lock = (update(models.LedgerChain).where(models.LedgerChain.chain == tenant)
            .values(seq=models.LedgerChain.seq).execution_options(synchronize_session=False))
    if s.execute(lock).rowcount == 0:
        ensure_chain(s, tenant)                 # 새 체인 — 테넌트 생성 시 미리 만들어 두므로 드물다
    head = s.execute(select(models.LedgerChain).where(models.LedgerChain.chain == tenant).with_for_update()
                     .execution_options(populate_existing=True)).scalar_one()
    rec = {"id": f"evd_{secrets.token_hex(8)}", "kind": kind, "refId": ref_id, "tenant": tenant,
           "body": body, "createdAt": now_iso()}
    h = record_hash(head.hash, rec)
    row = models.Evidence(id=rec["id"], kind=kind, ref_id=ref_id, tenant=tenant, body=body,
                          prev_hash=head.hash, hash=h, created_at=rec["createdAt"], chain=tenant)
    s.add(row)
    s.flush()
    head.seq, head.hash, head.count = row.seq, h, head.count + 1
    s.flush()                                   # 세션 autoflush=False — 다음 적재가 새 머리를 읽도록 즉시 반영
    if head.count % settings.ledger_checkpoint_every == 0:
        checkpoint(s, row.seq, h, tenant)
    return row


def append_many(s: Session, tenant: str, items: list[tuple[str, str, dict]]) -> list[models.Evidence]:
    """같은 체인에 여러 건을 한 번의 머리 잠금으로 적재 (증적 비동기 적재기의 묶음 쓰기, NFR-L5). 호출자가 commit 한다."""
    if not items:
        return []
    lock = (update(models.LedgerChain).where(models.LedgerChain.chain == tenant)
            .values(seq=models.LedgerChain.seq).execution_options(synchronize_session=False))
    if s.execute(lock).rowcount == 0:
        ensure_chain(s, tenant)
    head = s.execute(select(models.LedgerChain).where(models.LedgerChain.chain == tenant).with_for_update()
                     .execution_options(populate_existing=True)).scalar_one()
    prev, rows = head.hash, []
    for kind, ref_id, body in items:
        rec = {"id": f"evd_{secrets.token_hex(8)}", "kind": kind, "refId": ref_id, "tenant": tenant,
               "body": body, "createdAt": now_iso()}
        h = record_hash(prev, rec)
        rows.append(models.Evidence(id=rec["id"], kind=kind, ref_id=ref_id, tenant=tenant, body=body,
                                    prev_hash=prev, hash=h, created_at=rec["createdAt"], chain=tenant))
        prev = h
    s.add_all(rows)
    s.flush()                                   # 순서대로 INSERT — seq 는 적재 순서와 같다
    every, base = settings.ledger_checkpoint_every, head.count
    for i, row in enumerate(rows, 1):
        if (base + i) % every == 0:
            checkpoint(s, row.seq, row.hash, tenant)
    head.seq, head.hash, head.count = rows[-1].seq, rows[-1].hash, base + len(rows)
    s.flush()
    return rows


def checkpoint(s: Session, seq: int, hash_: str, chain: str) -> models.LedgerCheckpoint:
    existing = s.get(models.LedgerCheckpoint, seq)
    if existing:
        return existing
    kid = key_id()
    sig = base64.b64encode(signing_key().sign(checkpoint_message(seq, hash_, kid))).decode()
    cp = models.LedgerCheckpoint(seq=seq, hash=hash_, signature=sig, key_id=kid, created_at=now_iso(), chain=chain)
    s.add(cp)
    s.flush()
    return cp


# ── 조회·검증·내보내기 ─────────────────────────────────────────
def to_dict(r: models.Evidence) -> dict:
    return {"seq": r.seq, "id": r.id, "kind": r.kind, "refId": r.ref_id, "tenant": r.tenant, "body": r.body,
            "prevHash": r.prev_hash, "hash": r.hash, "createdAt": r.created_at, "chain": r.chain}


def records(s: Session, from_seq: int = 1, to_seq: int | None = None, kind: str | None = None,
            tenant: str | None = None, limit: int | None = None, desc: bool = False,
            chain: str | None = None) -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.seq >= from_seq)
    if to_seq is not None:
        q = q.where(models.Evidence.seq <= to_seq)
    if kind:
        q = q.where(models.Evidence.kind == kind)
    if tenant:
        q = q.where(models.Evidence.tenant == tenant)
    if chain:
        q = q.where(models.Evidence.chain == chain)
    q = q.order_by(models.Evidence.seq.desc() if desc else models.Evidence.seq)
    if limit:
        q = q.limit(limit)
    return list(s.scalars(q))


def chains(s: Session) -> list[str]:
    out = list(s.scalars(select(models.LedgerChain.chain).order_by(models.LedgerChain.chain)))
    if s.scalar(select(models.Evidence.seq).where(models.Evidence.chain == LEGACY).limit(1)) is not None:
        out.insert(0, LEGACY)
    return out


def _verify_chain(s: Session, chain: str, pub: str) -> dict:
    """머리를 먼저 읽고 그 seq 까지만 검증 — 비동기 적재기가 계속 쓰는 중에도 같은 시점의 체인을 본다.
    레코드는 서버 커서로 흘려 읽으며 하나씩 재계산한다(메모리 일정 — 수백만 건 체인도 작업 프로세스를 죽이지 않는다)."""
    head = s.get(models.LedgerHead, 1) if chain == LEGACY else s.get(models.LedgerChain, chain)
    upto = head.seq if head and head.seq else None
    E = models.Evidence
    q = select(E.seq, E.id, E.kind, E.ref_id, E.tenant, E.body, E.prev_hash, E.hash, E.created_at).where(E.chain == chain)
    cq = select(models.LedgerCheckpoint).where(models.LedgerCheckpoint.chain == chain)
    if upto is not None:
        q, cq = q.where(E.seq <= upto), cq.where(models.LedgerCheckpoint.seq <= upto)
    # 보존기한 만료로 앞부분을 지웠으면 마지막 앵커(서명 체크포인트 해시)에서 다시 시작 — 증명서 서명·앵커 사슬을 함께 확인
    purges = list(s.scalars(select(models.LedgerPurge).where(models.LedgerPurge.chain == chain).order_by(models.LedgerPurge.through_seq)))
    purge_msg = None
    if purges:
        from app import retention
        prior = None
        for pg in purges:
            if not retention.verify_cert(pg) or pg.certificate.get("previousAnchor") != prior:
                purge_msg = f"삭제 증명 {pg.id}: 서명·앵커 불일치"
                break
            prior = pg.anchor_hash
        q, cq = q.where(E.seq > purges[-1].through_seq), cq.where(models.LedgerCheckpoint.seq > purges[-1].through_seq)
    cps = list(s.scalars(cq.order_by(models.LedgerCheckpoint.seq)))
    want, seen = {cp.seq for cp in cps}, {}
    prev, n, msg, last = (purges[-1].anchor_hash if purges else GENESIS), 0, purge_msg, None
    for r in s.execute(q.order_by(E.seq).execution_options(yield_per=5000)):
        n += 1
        if msg is None:
            if r.prev_hash != prev:
                msg = f"seq {r.seq}: prevHash 불일치 (체인 단절)"
            elif record_hash(prev, {"id": r.id, "kind": r.kind, "refId": r.ref_id, "tenant": r.tenant, "body": r.body,
                                    "createdAt": r.created_at}) != r.hash:
                msg = f"seq {r.seq}: 해시 불일치 (내용 변조)"
            else:
                prev = r.hash
        if r.seq in want:
            seen[r.seq] = r.hash
        last = r.hash
    ok = msg is None
    bad_cp = [cp.seq for cp in cps
              if seen.get(cp.seq) != cp.hash or not verify_signature(pub, {"seq": cp.seq, "hash": cp.hash,
                                                                            "signature": cp.signature, "keyId": cp.key_id})]
    head_ok = (head.hash == last) if n and head else not n
    tail = s.scalar(select(func.count()).select_from(E).where(E.chain == chain, E.seq > upto)) if upto is not None else 0
    return {"chain": chain, "ok": ok and not bad_cp and bool(head_ok), "records": n, "checkpoints": len(cps),
            "detail": "체인 검증 통과" if ok else msg, "badCheckpoints": bad_cp, "appendedDuringVerify": tail,
            "head": {"seq": head.seq, "hash": head.hash} if head else None,
            "purged": {"throughSeq": purges[-1].through_seq, "records": sum(p.records for p in purges), "purges": len(purges)} if purges else None}


def verify(s: Session, chain: str | None = None) -> dict:
    """체인별 재계산 + 체크포인트 서명 검증 (운영 지표: 무결성 검증 성공률 100%). chain 생략 = 보이는 모든 체인."""
    pub = base64.b64encode(public_raw()).decode()
    results = [_verify_chain(s, c, pub) for c in ([chain] if chain else chains(s))]
    bad = [r for r in results if not r["ok"]]
    return {"ok": not bad, "records": sum(r["records"] for r in results),
            "checkpoints": sum(r["checkpoints"] for r in results),
            "detail": "; ".join(f"{r['chain']}: {r['detail']}" for r in bad) or "체인 검증 통과",
            "badCheckpoints": [x for r in results for x in r["badCheckpoints"]],
            "chains": results, "keyId": key_id()}


def export(s: Session, chain: str, from_seq: int = 1, to_seq: int | None = None) -> dict:
    """한 체인(테넌트)의 구간 — 다른 테넌트 레코드 없이 단독 검증된다."""
    recs = records(s, from_seq, to_seq, chain=chain)
    if not recs:
        return {}
    last = recs[-1]
    cp = checkpoint(s, last.seq, last.hash, chain)
    anchor = recs[0].prev_hash
    return {"format": BUNDLE_FORMAT, "exportedAt": now_iso(), "chain": chain, "anchor": anchor,
            "records": [to_dict(r) for r in recs],
            "checkpoint": {"seq": cp.seq, "hash": cp.hash, "signature": cp.signature, "keyId": cp.key_id},
            "publicKey": base64.b64encode(public_raw()).decode(),
            "verify": "python -m aegis verify-bundle <file>"}
