"""샌드박스·격리 풀 API (FR-P08, NFR-I, SCR-R04)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app import ledger, sandbox
from app.api.deps import Ctx, ctx, need, session

router = APIRouter(prefix="/v1", tags=["sandbox"], dependencies=[Depends(ctx)])


@router.get("/sandbox")
def status(c: Ctx = Depends(need("read"))):
    """격리 등급별 풀 용량·사용·대기·거부·회수와 커널이 실제로 주는 잠금 수단 (이 API 프로세스 기준)."""
    return sandbox.status()


@router.post("/sandbox:probe")
def probe(level: str = Query("L1", pattern="^L[12]$"), s: Session = Depends(session), c: Ctx = Depends(need("sandbox"))):
    """탈출 시도 점검 — 네트워크·프로세스 실행·데이터 디렉터리·키·메모리. L2 는 gVisor 경계(커널·네트워크·밖 파일·프로세스·덧씌움)
    + 안쪽 잠금 층(Epic 65). 결과는 원장에 남는다."""
    r = sandbox.probe(level)
    ledger.append(s, "sandbox", "probe", {"event": "escape_probe", "level": level, "ok": r["ok"], "by": c.name, "runtime": r.get("runsc"),
                                          "blocked": sum(x["blocked"] for x in r.get("results", [])),
                                          "total": len(r.get("results", [])), "caps": r.get("caps")})
    s.commit()
    return r
