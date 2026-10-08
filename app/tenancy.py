"""다중 테넌시 (FR-P13, SCR-R01) — 테넌트 생성(정책 네임스페이스·증적 체인 준비)과 교차 접근 차단 시험.

분리 원칙: 정책·증적·사건·점검·승인 레코드는 모두 tenant 열을 가진다. 정책 = (tenant, policy_id) 네임스페이스,
증적 = 테넌트별 해시 체인, 캐시·인덱스 접두 = 테넌트 ID. 테넌트 간 공유 없음.
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app import auth, db, ledger, models, policy

TENANT_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
RESERVED = {ledger.PLATFORM, ledger.LEGACY, "admin", "system"}
TENANT_TABLES = ("findings", "approvals", "evidence", "profile_applications", "scan_targets", "quarantine",
                 "incidents", "policies", "secret_leases", "finding_labels", "golden_samples",
                 "protected_targets")
MODELS = {"findings": models.Finding, "approvals": models.Approval, "evidence": models.Evidence,
          "profile_applications": models.ProfileApplication, "scan_targets": models.ScanTarget,
          "quarantine": models.Quarantine, "incidents": models.Incident, "policies": models.Policy,
          "secret_leases": models.SecretLease, "finding_labels": models.FindingLabel, "golden_samples": models.GoldenSample,
          "protected_targets": models.ProtectedTarget}


class TenantError(ValueError):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def out(t: models.Tenant, s: Session | None = None) -> dict:
    d = {"id": t.id, "name": t.name, "isolation": t.isolation, "retentionDays": t.retention_days,
         "region": t.region, "lang": t.lang, "active": t.active, "createdBy": t.created_by,
         "createdAt": t.created_at.isoformat() if t.created_at else None,
         "namespaces": {"policy": f"pol/{t.id}", "ledger": f"chain:{t.id}", "cachePrefix": f"{t.id}:"}}
    if s is not None:
        head = s.get(models.LedgerChain, t.id)
        app_ = s.scalars(select(models.ProfileApplication).where(models.ProfileApplication.tenant == t.id,
                                                                 models.ProfileApplication.active.is_(True))).first()
        d |= {"ledger": {"records": head.count if head else 0, "head": head.hash[:16] if head else None},
              "profile": app_.profile_id if app_ else None,
              "users": s.scalar(select(func.count()).select_from(models.User).where(models.User.tenant == t.id)) or 0}
    return d


def require(s: Session, tenant: str, cached: bool = False) -> models.Tenant:
    """쓰기 전에 테넌트 존재·활성 확인 — 식별자가 틀린 레코드는 저장하지 않는다.
    cached = 인라인 판정 경로만 — hotcache(TTL 2초, 이 프로세스의 테넌트 쓰기 커밋 시 즉시 무효화)의 읽기 전용 스냅샷."""
    if cached:
        from app import hotcache
        t = hotcache.get(("tenant", tenant), lambda: hotcache.detach(s, s.get(models.Tenant, tenant)))
    else:
        t = s.get(models.Tenant, tenant)
    if t is None:
        raise TenantError(404, f"tenant {tenant} 없음")
    if not t.active:
        raise TenantError(409, f"tenant {tenant} 비활성")
    return t


def create(s: Session, tid: str, name: str, by: str, isolation: str = "logical", retention_days: int = 90,
           region: str = "kr", lang: str = "ko") -> models.Tenant:
    if not TENANT_ID.match(tid) or tid in RESERVED:
        raise TenantError(422, "테넌트 ID 는 소문자로 시작하는 소문자·숫자·- 2~32자 (예약어 제외)")
    if isolation != "logical":
        raise TenantError(422, "물리 분리는 전용 설치(원장·키·샌드박스 풀 분리)가 필요하다 — 이 설치는 논리 분리만 제공")
    if s.get(models.Tenant, tid):
        raise TenantError(409, f"tenant {tid} 이미 있음")
    t = models.Tenant(id=tid, name=name, isolation=isolation, retention_days=retention_days, region=region,
                      lang=lang, active=True, created_by=by, created_at=datetime.now(timezone.utc))
    s.add(t)
    s.flush()
    ledger.ensure_chain(s, tid)
    pol = policy.ensure_default(s, tid)                    # 테넌트 정책 네임스페이스 — 기본 정책 사본 v1
    ledger.append(s, "tenant", tid, {"event": "tenant_created", "name": name, "isolation": isolation,
                                     "retentionDays": retention_days, "region": region, "policy": pol, "by": by})
    ledger.append(s, "tenant", tid, {"event": "tenant_created", "name": name, "by": by}, tid)
    return t


def update(s: Session, t: models.Tenant, by: str, name: str | None = None, retention_days: int | None = None,
           active: bool | None = None) -> models.Tenant:
    changes = {}
    if name and name != t.name:
        changes["name"], t.name = name, name
    if retention_days is not None and retention_days != t.retention_days:
        changes["retentionDays"], t.retention_days = retention_days, retention_days
    if active is not None and active != t.active:
        if t.id == "default" and not active:
            raise TenantError(409, "기본 테넌트는 비활성화할 수 없다")
        changes["active"], t.active = active, active
    if changes:
        ledger.append(s, "tenant", t.id, {"event": "tenant_updated", "changes": changes, "by": by})
    return t


# ── 교차 접근 차단 시험 (SCR-R01 #7, ST-04) ──────────────────────
def _probe_ctx(s: Session, tenant: str) -> auth.Ctx:
    """테넌트 a 에 묶인 가상 주체 — DB 에 저장하지 않는다."""
    u = models.User(id="probe", username=f"probe@{tenant}", display_name="probe", roles=["security_engineer"],
                    tenant=tenant, kind="human", active=True)
    return auth.Ctx(user=u, scope=tenant, perms=auth.permissions(u))


def isolation_test(s: Session, by: str) -> dict:
    tenants = [t.id for t in s.scalars(select(models.Tenant).where(models.Tenant.active.is_(True)).order_by(models.Tenant.id))]
    checks: list[dict] = []

    def check(cid: str, title: str, ok: bool, detail: str):
        checks.append({"id": cid, "title": title, "ok": bool(ok), "detail": detail})

    pairs = [(a, b) for a in tenants for b in tenants if a != b][:12]
    if len(tenants) < 2:
        pairs = [(tenants[0], "__other__")] if tenants else []
    # 1. 토큰 범위 — a 주체가 b 를 지정하면 거부
    denied = 0
    for a, b in pairs:
        c = _probe_ctx(s, a)
        try:
            c.tenant_for(b)
        except auth.AuthError as exc:
            denied += exc.status == 403
        try:
            c.read_filter(b)
        except auth.AuthError as exc:
            denied += exc.status == 403
    check("token-scope", "테넌트 토큰 → 다른 테넌트 판정·조회 403", denied == 2 * len(pairs), f"{denied}/{2 * len(pairs)} 거부")
    # 2. 정책 네임스페이스 — 각 테넌트 관문이 읽는 정책은 자기 테넌트 것뿐
    leaks = [t for t in tenants if (p := policy.latest(s, "default", t)) is not None and p.tenant != t]
    missing = [t for t in tenants if policy.latest(s, "default", t) is None]
    check("policy-ns", "정책 → 다른 테넌트 관문 적용 거부", not leaks and not missing,
          f"누수 {leaks or 0} · 정책 없는 테넌트 {missing or 0}")
    # 3. 테넌트 식별자 누락 레코드 0
    blank = {name: n for name, m in MODELS.items()
             if (n := s.scalar(select(func.count()).select_from(m).where(or_(m.tenant.is_(None), m.tenant == ""))))}
    check("tenant-id", "모든 레코드에 테넌트 식별자", not blank, f"누락 {blank or 0}")
    # 4. 원장 파티션 — 레코드의 체인 = 테넌트
    cross = s.scalar(select(func.count()).select_from(models.Evidence)
                     .where(models.Evidence.chain != ledger.LEGACY, models.Evidence.chain != models.Evidence.tenant)) or 0
    check("ledger-partition", "원장 파티션 교차 기록 0", cross == 0, f"체인≠테넌트 {cross}건")
    # 5. 테넌트 체인 단독 검증
    bad = [t for t in tenants if s.get(models.LedgerChain, t) and not ledger.verify(s, t)["ok"]]
    check("ledger-verify", "테넌트 체인 단독 무결성 검증", not bad, f"실패 {bad or 0}")
    # 6. DB 계층 RLS (PostgreSQL)
    bind = s.get_bind()
    if bind.dialect.name == "postgresql":
        rows = s.execute(text("SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                              "WHERE relname = ANY(:t) AND relkind = 'r'"), {"t": list(TENANT_TABLES)}).all()
        off = sorted({r[0] for r in rows if not (r[1] and r[2])} | (set(TENANT_TABLES) - {r[0] for r in rows}))
        role = s.execute(text("SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")).one()
        leaked = 0
        if len(tenants) >= 2:
            a = tenants[0]
            with db.engine.connect() as conn:              # 별도 연결 — 테넌트 a 범위에서 다른 테넌트 행이 보이는가
                conn.execute(text("SELECT set_config('aegis.tenant', :t, true)"), {"t": a})
                for tbl in TENANT_TABLES:
                    leaked += conn.execute(text(f"SELECT count(*) FROM {tbl} WHERE tenant <> :t"), {"t": a}).scalar() or 0
                conn.rollback()
        check("rls", "DB 행 수준 보안(RLS) — 범위 밖 행 0", not off and not role[1] and not role[2] and leaked == 0,
              f"역할 {role[0]} (super={role[1]}, bypassrls={role[2]}) · RLS 꺼진 표 {off or 0} · 교차 조회 {leaked}건")
    else:
        check("rls", "DB 행 수준 보안(RLS)", True, f"{bind.dialect.name} — RLS 없음, 앱 계층 강제만 (prod PostgreSQL 에서 이중)")
    # 7. 없는 테넌트 쓰기 거부
    try:
        require(s, f"nx-{secrets.token_hex(3)}")
        rejected = False
    except TenantError:
        rejected = True
    check("unknown-tenant", "없는 테넌트 식별자로 저장 거부", rejected, "404" if rejected else "저장됨")

    failed = [c["id"] for c in checks if not c["ok"]]
    result = {"ok": not failed, "passed": len(checks) - len(failed), "total": len(checks), "failed": failed,
              "tenants": tenants, "checks": checks, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "by": by}
    ledger.append(s, "tenancy", "isolation-test", {"event": "isolation_test", **result})
    if failed:                                             # 위반 = 사건 (ST-04)
        s.add(models.Incident(id=f"inc_{secrets.token_hex(6)}", tenant=ledger.PLATFORM, key="platform|tenancy|D5",
                              title=f"테넌트 교차 접근 시험 실패: {', '.join(failed)}", domain="D5", severity="high",
                              status="open", contained=False, trace_ids=[], finding_ids=[], agent_ids=[],
                              rule_ids=[f"PLATFORM.tenancy.{f}" for f in failed]))
    return result


def last_test(s: Session) -> dict | None:
    rows = ledger.records(s, kind="tenancy", limit=1, desc=True)
    return rows[0].body if rows else None
