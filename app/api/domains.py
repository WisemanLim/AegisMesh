"""도메인 상세 화면 API (SCR-E02~F04 …) — 판정 검사·유출 차단 현황·격리·자격증명·무단 접근, 삭제 전파·재현 시험."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import domains, privacy
from app.api.deps import Ctx, ctx, need, read_tenant, session, write_tenant

router = APIRouter(prefix="/v1", tags=["domains"], dependencies=[Depends(ctx)])


def _t(c: Ctx, tenant: str | None) -> str:
    return read_tenant(c, tenant) or "default"


def _priv(fn):
    try:
        return fn()
    except privacy.PrivacyError as exc:
        raise HTTPException(exc.status, exc.msg) from exc


@router.get("/findings/{fid}/inspect")
def inspect_finding(fid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """입력 검사 뷰어 (SCR-E02) — 판정 근거 + 판정 기록의 요청 모양(세그먼트 출처·신뢰·길이). 원문 없음."""
    out = domains.inspect_finding(s, read_tenant(c, tenant), fid)
    if out is None:
        raise HTTPException(404, f"finding {fid} 없음")
    return out


@router.get("/domains/d1/exfil")
def d1_exfil(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.exfil(s, _t(c, tenant))


@router.get("/domains/d2/isolation")
def d2_isolation(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.isolation(s, _t(c, tenant))


@router.post("/domains/d2/isolation:regress")
def d2_regress(tenant: str | None = None, n: int = Query(100, ge=10, le=1000), s: Session = Depends(session),
               c: Ctx = Depends(need("scan"))):
    """교차 조회 회귀 시험 — 테넌트·주체·세션 경계 넘는 합성 요청 n 건씩 D2-02 판정, 놓친 건 = 누출."""
    r = domains.cross_scope_regression(s, write_tenant(s, c, tenant), c.name, n)
    s.commit()
    return r


# ── 삭제 전파 (D2-07) ─────────────────────────────────────────
class ErasureIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)       # 해시만 남긴다
    basis: str = Field(min_length=1, max_length=300)
    days: int = Field(10, ge=1, le=90)


class StoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    store: str
    status: str
    note: str = Field("", max_length=200)


@router.get("/erasure")
def erasure_list(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = _t(c, tenant)
    return {"tenant": t, "stores": privacy.STORES, "items": privacy.requests(s, t)}


@router.post("/erasure", status_code=201)
def erasure_create(body: ErasureIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = write_tenant(s, c, tenant)
    r = _priv(lambda: privacy.create(s, t, body.subject, body.basis, body.days, c.name))
    s.commit()
    return r


@router.get("/erasure/{rid}")
def erasure_get(rid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    return _priv(lambda: privacy.get(s, _t(c, tenant), rid))


@router.post("/erasure/{rid}/stores")
def erasure_store(rid: str, body: StoreIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = write_tenant(s, c, tenant)
    r = _priv(lambda: privacy.report(s, t, rid, body.store, body.status, c.name, body.note))
    s.commit()
    return r


@router.post("/erasure/{rid}:verify")
def erasure_verify(rid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = write_tenant(s, c, tenant)
    r = _priv(lambda: privacy.verify(s, t, rid, c.name))
    s.commit()
    return r


@router.post("/erasure/{rid}:certify")
def erasure_certify(rid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = write_tenant(s, c, tenant)
    r = _priv(lambda: privacy.certify(s, t, rid, c.name))
    s.commit()
    return r


# ── 학습 데이터 재현 시험 (D2-05) ───────────────────────────────
class RecallIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=80)
    version: str = Field(min_length=1, max_length=40)
    outputs: list[str] = Field(min_length=1, max_length=2000)
    miaAuc: float | None = Field(None, ge=0, le=1)
    dpEpsilon: float | None = Field(None, ge=0)
    dedupRate: float | None = Field(None, ge=0, le=1)


@router.get("/recall-tests")
def recall_list(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = _t(c, tenant)
    return {"tenant": t, "items": privacy.recall_history(s, t)}


@router.post("/recall-tests", status_code=201)
def recall_run(body: RecallIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("privacy"))):
    t = write_tenant(s, c, tenant)
    r = _priv(lambda: privacy.recall_test(s, t, body.model, body.version, body.outputs, c.name, body.miaAuc, body.dpEpsilon, body.dedupRate))
    s.commit()
    return r


# ── D3 도구 오남용 (SCR-G02·G03·G04) ───────────────────────────
@router.get("/domains/d3/calls")
def d3_calls(tenant: str | None = None, limit: int = Query(30, ge=1, le=200), s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return {"items": domains.calls(s, read_tenant(c, tenant), limit)}


@router.get("/domains/d3/calls/{trace}")
def d3_call(trace: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    out = domains.call(s, read_tenant(c, tenant), trace)
    if out is None:
        raise HTTPException(404, f"도구 관문 판정 {trace} 없음")
    return out


@router.get("/domains/d3/sandbox")
def d3_sandbox(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d3_sandbox(s, read_tenant(c, tenant))


@router.get("/domains/d3/registry")
def d3_registry(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d3_registry(s, _t(c, tenant))


# ── D4 모델 환각 (SCR-H02·H03·H04) ─────────────────────────────
@router.get("/domains/d4/grounding/{fid}")
def d4_grounding(fid: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    out = domains.d4_grounding(s, read_tenant(c, tenant), fid)
    if out is None:
        raise HTTPException(404, f"finding {fid} 없음")
    return out


@router.get("/domains/d4/decisions")
def d4_decisions(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d4_decisions(s, read_tenant(c, tenant))


@router.get("/domains/d4/propagation")
def d4_propagation(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d4_propagation(s, _t(c, tenant))


class CorrectionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    traceId: str | None = None
    source: str | None = None
    status: str = "corrected"
    note: str = Field("", max_length=200)


@router.post("/domains/d4/corrections")
def d4_correct(body: CorrectionIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("incident"))):
    """전파 지점 정정 상태 기록(traceId) 또는 소급 정정(source — 정정 완료 아닌 지점에 정정 요청). 원장 추가 전용."""
    t = write_tenant(s, c, tenant)
    try:
        r = (domains.retro_correct(s, t, body.source, c.name) if body.source
             else domains.correct(s, t, body.traceId or "", body.status, c.name, body.note))
    except KeyError:
        raise HTTPException(404, f"출처 {body.source} 없음") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return r


# ── D5 접근 통제 (SCR-I02·I03·I04) ──────────────────────────────
@router.get("/domains/d5/identity")
def d5_identity(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """워크로드 신원·정적 키·에이전트 카드·신원-능력 바인딩. SVID 표는 신원 권한(플랫폼)만."""
    return domains.d5_identity(s, read_tenant(c, tenant), "identity" in c.perms)


@router.get("/domains/d5/tokens")
def d5_tokens(tenant: str | None = None, hours: int = Query(24, ge=1, le=720), s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d5_tokens(s, read_tenant(c, tenant), hours)


@router.get("/domains/d5/authz")
def d5_authz(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d5_authz(s, _t(c, tenant))


@router.post("/domains/d5/authz:drift-scan")
def d5_drift(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("scan"))):
    r = domains.drift_scan(s, write_tenant(s, c, tenant), c.name)
    s.commit()
    return r


# ── D6 자율 과잉 (SCR-J02·J03·J04) ──────────────────────────────
@router.get("/domains/d6/autonomy")
def d6_autonomy(target: str | None = None, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d6_autonomy(s, _t(c, tenant), target)


@router.get("/domains/d6/runs")
def d6_runs(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return {"items": domains.d6_runs(s, read_tenant(c, tenant))}


@router.get("/domains/d6/runs/{trace}")
def d6_run(trace: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    out = domains.d6_run(s, read_tenant(c, tenant), trace)
    if out is None:
        raise HTTPException(404, f"실행 {trace} 없음")
    return out


@router.get("/domains/d6/budgets")
def d6_budgets(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d6_budgets(s, _t(c, tenant))


# ── D7·D8·D9 (SCR-K02~K04·L02~L04·M02~M04) ─────────────────────
ARTIFACT_KINDS = {"review": ["mcp_server", "plugin", "skill", "tool"], "sbom": ["sbom", "package"], "integrity": ["dataset", "model", "api_provider"],
                  "index": ["index_update"], "posture": ["iac", "cloud_config", "db_accounts"], "runtime": ["runtime_events", "endpoint_posture"],
                  "network": ["crypto_inventory", "network_policy", "traffic_stats"]}


@router.get("/domains/artifacts/{group}")
def artifacts(group: str, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    """상시 점검 대상·최근 점검·격리·결정 (도메인 상세 화면 공통)."""
    if group not in ARTIFACT_KINDS:
        raise HTTPException(404, f"그룹 {group} 없음 ({sorted(ARTIFACT_KINDS)})")
    return domains.artifacts(s, read_tenant(c, tenant), ARTIFACT_KINDS[group])


class SupplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=200)
    decision: str = Field(pattern="^(approve|conditional|reject|retest|accept-change|restore|allow|pin-update|release)$")
    reason: str = Field(min_length=1, max_length=300)


@router.post("/domains/decisions")
def supply_decide(body: SupplyIn, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("scan"))):
    t = write_tenant(s, c, tenant)
    try:
        r = domains.decide_supply(s, t, body.kind, body.name, body.decision, body.reason, c.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    s.commit()
    return r


@router.get("/domains/d8/memory")
def d8_memory(tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d8_memory(s, read_tenant(c, tenant))


@router.get("/domains/d8/context")
def d8_context(trace: str | None = None, tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d8_context(s, read_tenant(c, tenant), trace)


@router.get("/domains/d8/bias")
def d8_bias(days: int = Query(30, ge=1, le=90), tenant: str | None = None, s: Session = Depends(session), c: Ctx = Depends(need("read"))):
    return domains.d8_bias(s, read_tenant(c, tenant), days)
