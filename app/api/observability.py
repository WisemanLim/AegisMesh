"""관측 파이프라인·SLO·오탐 예산 API (FR-P09, NFR-O3, SCR-Q04·Q05)."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import (
    dr,
    evidence_writer,
    gating,
    hotcache,
    kms,
    ledger,
    models,
    orchestrator,
    telemetry,
    tls,
)
from app.api.deps import Ctx, ctx, need, read_tenant, session
from app.core.config import settings

router = APIRouter(prefix="/v1", tags=["observability"], dependencies=[Depends(ctx)])
FP_BUDGET = 0.005                     # NFR-Q1 오탐 예산 (에이전트별 골든셋 FP ≤ 0.5%)


def _p95(xs: list[float]) -> float:
    xs = sorted(xs)
    return round(xs[max(0, int(len(xs) * 0.95) - 1)], 3) if xs else 0.0


@router.get("/observability")
def observability(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    t = read_tenant(c, tenant)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    q = select(models.Evidence).where(models.Evidence.kind == "gate", models.Evidence.created_at >= since)
    if t:
        q = q.where(models.Evidence.tenant == t)
    recs = list(s.scalars(q.order_by(models.Evidence.seq.desc()).limit(5000)))
    slo = {}
    for g, budget in orchestrator.GATE_BUDGET_MS.items():
        xs = [r.body.get("latencyMs", 0) for r in recs if r.body.get("gate") == g]
        p95 = _p95(xs)
        slo[g] = {"budgetMs": budget, "p95Ms": p95, "records": len(xs), "burn": round(p95 / budget, 3) if budget else 0,
                  "breach": bool(xs) and p95 > budget}
    overhead = round(sum(r.body.get("latencyMs", 0) for r in recs) / len(recs), 3) if recs else 0.0
    rt = ledger.records(s, kind="redteam", limit=1, desc=True)
    rt_body = rt[0].body if rt else {}
    fp = [{"agent": r["agent"], "fpRate": r["fpRate"], "budget": FP_BUDGET, "consumed": round(r["fpRate"] / FP_BUDGET, 3),
           "detectionRate": r["detectionRate"], "baseline": r["baseline"], "regression": r["detectionRate"] < r["baseline"]}
          for r in rt_body.get("results", [])]
    alert_only = [a.id for a in s.scalars(select(models.Agent).where(models.Agent.status == "alert_only"))]
    return telemetry.status() | {
        "tenant": t or "*",
        "slo": {"gates": slo, "avgGateOverheadMs": overhead, "records24h": len(recs),
                "fpBudget": FP_BUDGET, "fp": sorted(fp, key=lambda x: -x["consumed"])[:20],
                "fpOverBudget": [x["agent"] for x in fp if x["fpRate"] > FP_BUDGET],
                "regressions": [x["agent"] for x in fp if x["regression"]],
                "redteamAt": rt[0].created_at if rt else None},
        "alertOnly": alert_only,
        "evidencePipeline": evidence_writer.status() | {"process": "이 api 작업 프로세스 기준"},     # NFR-L5
        "hotCache": dict(hotcache.STATS) | {"ttlSec": settings.hot_cache_ttl_sec},
        "deepCheck": dict(gating.DEEP_STATS) | {"enabled": bool(settings.guard_url), "queueMax": settings.guard_queue_max,
                                               "workers": settings.guard_workers, "process": "이 api 작업 프로세스 기준"},   # Epic 50
        "rollbackRules": ["관문 p95 가 예산을 넘으면 경보(D10-07) — 상시 계열 재배치 제안(/gates)",
                          "에이전트 오탐률 > 0.5% → 경보 전용(alert_only) 강등, 재심사(R5) 통과 시 복귀",
                          "레드팀 탐지율 < 기준선 → 회귀 사건, 정책 롤백은 2인 승인(/policies)"],
    }



@router.get("/observability/dr")
def dr_status(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """재해 복구 상태 (NFR-A5) — 동기 대기 서버·WAL 보관 시각·최근 복구 훈련. local(SQLite)은 대상 아님."""
    return dr.status(s)


@router.get("/observability/tls")
def tls_status(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """내부 상호 TLS 상태 (NFR-D3) — 구간·인증서 만료·이 api 의 DB 연결 TLS. local 은 평문(enabled false)."""
    return tls.status(s)


@router.get("/observability/kms")
def kms_status(s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """저장 암호화 상태 (NFR-D2) — KMS·KEK 버전·표별 암호화 비율·최근 증적·키 파일 포장 여부. 값은 보이지 않는다."""
    return kms.status(s)

class MaskIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/observability:mask-test")
def mask_test(body: MaskIn, c: Ctx = Depends(need("read"))):
    """수집기와 같은 규칙으로 미리 보기 — 저장·전송 없음."""
    masked, hits = telemetry.mask(body.text)
    return {"masked": masked, "rules": hits, "changed": masked != body.text}


@router.post("/observability:test-log")
def test_log(body: MaskIn, c: Ctx = Depends(need("governance"))):
    """시험 로그를 실제 파이프라인으로 보낸다 — 수집기 debug 출력에서 치환 결과를 확인한다(원문은 앱에 남지 않음)."""
    preview, hits = telemetry.mask(body.text)
    if not telemetry.enabled():
        return {"sent": False, "reason": "OTEL_ENDPOINT 미설정 — 내보내기 비활성", "preview": preview, "rules": hits}
    trace_id = telemetry.test_log(body.text, c.name, c.scope)
    telemetry.flush()
    return {"sent": True, "traceId": trace_id, "preview": preview, "rules": hits, "stats": telemetry.STATS}
