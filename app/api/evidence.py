"""증적 원장 API — 조회·무결성 검증·서명 묶음 내보내기 (FR-P05, PRD §12.6). 수정·삭제 API 는 없다(DP9).
체인 = 테넌트(FR-P13). 테넌트 주체는 자기 체인만 보고·검증·내보낸다."""
import base64

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import ledger
from app.api.deps import Ctx, ctx, need, platform_scope, read_tenant, session

router = APIRouter(prefix="/v1", tags=["evidence"], dependencies=[Depends(ctx)])


@router.get("/evidence")
def list_evidence(kind: str | None = None, tenant: str | None = None, limit: int = Query(50, le=500),
                  before: int | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    rows = ledger.records(s, 1, (before - 1) if before else None, kind, read_tenant(c, tenant), limit, desc=True)
    return {"items": [ledger.to_dict(r) for r in rows]}


@router.get("/evidence:verify")
def verify(chain: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return ledger.verify(s, read_tenant(c, chain))


@router.get("/evidence:export")
def export(from_seq: int = Query(1, alias="from", ge=1), to_seq: int | None = Query(None, alias="to"),
           chain: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("evidence.export"))):
    ch = read_tenant(c, chain) or "default"
    bundle = ledger.export(s, ch, from_seq, to_seq)
    if not bundle:
        raise HTTPException(404, "내보낼 레코드 없음")
    cp = bundle["checkpoint"]
    ledger.append(s, "export", f"{bundle['records'][0]['seq']}-{cp['seq']}",
                  {"event": "evidence_exported", "by": c.name, "chain": ch, "records": len(bundle["records"]),
                   "checkpoint": cp["seq"], "keyId": cp["keyId"]}, ch)
    s.commit()
    return bundle


@router.get("/evidence/public-key")
def public_key():
    return {"algorithm": "Ed25519", "keyId": ledger.key_id(), "publicKey": base64.b64encode(ledger.public_raw()).decode()}


# ── 보존기한 만료 (NFR-S · R07) — 삭제 API 가 아니라 2인 승인 배치 요청과 서명 삭제 증명 조회 ──────────
def _chains(s: Session, c: Ctx) -> list[str]:
    return [x for x in ledger.chains(s) if x != ledger.LEGACY] if c.scope == "*" else [c.scope]


@router.get("/evidence/retention")
def retention_overview(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    from app import retention
    return retention.overview(s, _chains(s, c))


class RetentionIn(BaseModel):
    chain: str


@router.post("/evidence/retention:request")
def retention_request(body: RetentionIn, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    """만료 대상(서명 체크포인트까지·법적 보존 앞까지)을 2인 승인으로 요청 — 실행은 승인 뒤 배치."""
    from app import retention
    if body.chain not in _chains(s, c):
        raise HTTPException(404, f"chain {body.chain} 없음")
    try:
        r = retention.request(s, body.chain, c.name)
    except retention.RetentionError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    s.commit()
    return r


@router.get("/evidence/bus")
def bus_status(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """발견 버스(Epic 60) — NATS JetStream 스트림 상태·중계 커서·지연(원장 seq 차이). 플랫폼 범위."""
    from app import bus
    platform_scope(s, c)
    return bus.status(s)


@router.get("/evidence/rewrap")
def rewrap_overview(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """원장 저장 재암호화(Epic 57) — 평문 기록 수·구간·재암호화 창(서명 증명서)·승인 대기·현재 KEK. 플랫폼 범위."""
    from app import ledger_rewrap
    platform_scope(s, c)
    return ledger_rewrap.overview(s)


@router.post("/evidence/rewrap:request")
def rewrap_request(s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    """암호화 전 원장 기록 재암호화를 2인 승인으로 요청 — 승인되면 창이 열리고 worker·`make ledger-rewrap` 이 묶음으로 실행."""
    from app import ledger_rewrap
    platform_scope(s, c)
    try:
        r = ledger_rewrap.request(s, c.name)
    except ledger_rewrap.RewrapError as exc:
        raise HTTPException(exc.status, exc.msg) from exc
    s.commit()
    return r


@router.get("/evidence/purges/{pid}")
def purge_certificate(pid: str, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """서명 삭제 증명서 — 원장 공개키(/v1/evidence/public-key)로 오프라인 검증."""
    from app import models, retention
    r = s.get(models.LedgerPurge, pid)
    if r is None or r.chain not in _chains(s, c):
        raise HTTPException(404, f"purge {pid} 없음")
    return retention.purge_out(r)
