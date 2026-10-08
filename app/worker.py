"""상시 점검 worker (compose 서비스 `worker`) — 등록된 점검 대상을 주기 실행한다. 호스트 프로세스 매니저 없음.

  python -m app.worker            # 루프 (WORKER_INTERVAL_SEC 마다 due 대상 실행)
  python -m app.worker --once     # 한 번만
"""
import argparse
import logging
import signal
import time

from app import db, scanner
from app.core.config import settings

log = logging.getLogger("aegismesh.worker")
_stop = False


def _due(s, kind: str, interval: int) -> bool:
    from app import ledger
    from app.format_utils import iso_to_epoch
    last = ledger.records(s, kind=kind, limit=1, desc=True)
    return not last or time.time() - iso_to_epoch(last[0].created_at) >= interval


def _due_quality(s, ref_like: str, interval: int) -> bool:
    from sqlalchemy import select

    from app import models
    from app.format_utils import iso_to_epoch
    last = s.scalars(select(models.Evidence.created_at).where(models.Evidence.kind == "quality", models.Evidence.ref_id.like(ref_like))
                     .order_by(models.Evidence.seq.desc()).limit(1)).first()
    return not last or time.time() - iso_to_epoch(last) >= interval


def scheduled(s) -> list[dict]:
    """주기 작업: 레드팀 캠페인(FR-P10)·거버넌스 자체 점검(D10)·테넌트 교차 접근 시험(FR-P13). 실행 기록은 원장에 남는다."""
    from app import governance, redteam
    out = []
    if _due(s, "redteam", settings.redteam_interval_sec):
        r = redteam.run_campaign(s, "worker")
        s.commit()
        out.append({"job": "redteam", "verdict": r["verdict"], "regressions": len(r["regressions"])})
    if _due(s, "governance", settings.governance_interval_sec):
        r = governance.assess(s, "worker")
        from app import ledger
        ledger.append(s, "governance", "assess", {"event": "assessed", "verdict": r["verdict"],
                                                  "hits": [h["ruleId"] for h in r["hits"]], "by": "worker"})
        s.commit()
        out.append({"job": "governance", "verdict": r["verdict"], "hits": len(r["hits"])})
    from app import identity
    rot = identity.rotate(s, "worker")                          # 워크로드 신원 수명 50% 회전 (FR-P07)
    s.commit()
    if rot["rotated"]:
        out.append({"job": "identity", "rotated": rot["rotated"]})
    from app import quality
    if _due_quality(s, "qcheck", settings.quality_check_interval_sec):   # NFR-Q6 오탐 예산 — 80% 경보·초과 강등·7일 복귀
        acts = quality.enforce(s, "worker")
        from app import ledger as _l
        _l.append(s, "quality", "qcheck", {"event": "fp_budget_checked", "actions": acts, "by": "worker"})
        s.commit()
        if acts:
            out.append({"job": "fp-budget", "actions": acts})
    if _due_quality(s, "golden", settings.golden_interval_sec):            # NFR-Q1 주간 골든셋 1만 건 재생
        r = quality.golden_replay(s, "worker")
        s.commit()
        out.append({"job": "golden", "fpRate": r["overallFpRate"], "overTarget": r["overTarget"]})
    from app import approvals as _apr
    if (n := _apr.expire_due(s)):                                      # 승인 만료 = 자동 거절 (SCR-O06)
        s.commit()
        out.append({"job": "approval-expiry", "expired": n})
    if _due(s, "slo", 3600):                                         # SCR-D02 비용·SLO 경보(관문 p95·연속 초과·비용·오탐 예산)
        from app import gates
        alerts = gates.slo_check(s, "worker")
        s.commit()
        if alerts:
            out.append({"job": "slo", "alerts": len(alerts)})
    if _due(s, "fairness", settings.fairness_interval_sec):           # SCR-N06 공정성 정례 측정(주 1회) — 적용 중인 보호 대상마다
        from sqlalchemy import select as _sel

        from app import compliance, models as _m
        apps = {(a.tenant, a.target) for a in s.scalars(_sel(_m.ProfileApplication).where(_m.ProfileApplication.active.is_(True)))}
        rs = [compliance.measure(s, t, tg, 7, "worker") for t, tg in sorted(apps)]
        s.commit()
        out.append({"job": "fairness", "targets": len(rs), "over": sum(bool(r["over"]) for r in rs)})
    if _due(s, "retention", 86400):                                    # 증적 보존기한 만료 — 대상 체인마다 2인 승인 요청(실행은 승인 뒤)
        from app import ledger as _lg
        from app import retention
        reqs = retention.due_requests(s)
        _lg.append(s, "retention", "scan", {"event": "retention_scanned", "requests": [r["approvalRef"] for r in reqs], "by": "worker"})
        s.commit()
        if reqs:
            out.append({"job": "retention", "requests": len(reqs)})
    if _due(s, "pins", 86400):                                         # 고정 판(MDS3·DB-IP) 낡음 점검 — 매일, 낡으면 알림(Epic 58)
        from app import ledger as _lp
        from app import pins
        r = pins.check()
        _lp.append(s, "pins", "check", {"event": "pins_stale" if r["stale"] else "pins_checked", "stale": r["stale"],
                                        "items": [{k: i.get(k) for k in ("name", "version", "nextUpdate", "built", "ageDays", "stale")} for i in r["items"]],
                                        "by": "worker"})
        s.commit()
        out.append({"job": "pins", "stale": r["stale"]})
    from app import ledger_rewrap
    if ledger_rewrap.active(s) is not None:                            # 원장 재암호화 창(2인 승인, Epic 57) — 주기마다 최대 60초씩
        r = ledger_rewrap.run(s, budget_sec=60)
        if r.get("rewrapped") or r.get("completed"):
            out.append({"job": "ledger-rewrap"} | {k: r[k] for k in ("window", "rewrapped", "remaining") if k in r})
    from app import samples as _smp
    if (n := _smp.trim(s)):                                            # 미리보기 표본 — 만료·N건 초과 삭제(OQ1)
        s.commit()
        out.append({"job": "samples-trim", "removed": n})
    if _due_quality(s, "corpus:%", settings.corpus_interval_sec):      # 공개 공격 코퍼스 정기 실측(NFR-Q2) — 반입본이 있을 때만
        from app import corpora
        if (a := corpora.available()) and a["integrity"]:
            r = corpora.run(s, "worker")
            s.commit()
            out.append({"job": "corpus", "runs": len(r["rows"])})
    if _due(s, "kpi", 86400):                                          # 성공 지표 일 1회 스냅샷(원장 전체 검증 포함, PRD §15.1)
        from app import success
        r = success.snapshot(s, "worker")
        s.commit()
        out.append({"job": "kpi", "integrity": r["integrity"]["ok"], "measured": r["summary"]["measured"]})
    if _due(s, "tenancy", settings.tenancy_test_interval_sec):
        from app import tenancy
        r = tenancy.isolation_test(s, "worker")                  # SCR-R01 교차 접근 차단 매일 자동 시험
        s.commit()
        out.append({"job": "tenancy", "ok": r["ok"], "passed": f"{r['passed']}/{r['total']}"})
    return out


def tick() -> list[dict]:
    results = []
    with db.system_session() as s:
        try:
            for j in scheduled(s):
                log.warning("job %s → %s", j["job"], j)
                results.append(j)
        except Exception:  # noqa: BLE001
            s.rollback()
            log.exception("주기 작업 실패")
        for t in scanner.due_targets(s):
            try:
                r = scanner.run_scan(s, t.artifact, t.tenant, t, by="worker")
                s.commit()
                results.append({k: r[k] for k in ("target", "verdict", "quarantine")})
                log.warning("scan %s %s → %s%s", t.id, t.name, r["verdict"], f" (격리 {r['quarantine']})" if r["quarantine"] else "")
            except Exception:  # noqa: BLE001 — 대상 하나의 실패가 다른 대상 점검을 막지 않는다
                s.rollback()
                log.exception("scan %s 실패", t.id)
    return results


def wait_for_schema(timeout: int = 600) -> bool:
    """설치 직후(마이그레이션 Job·`make db-migrate` 전)에는 표가 없다 — 재시작 대신 기다린다."""
    from app import models
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with db.system_session() as s:
                s.query(models.LedgerChain).limit(1).all()
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("DB 스키마 대기 (%s) — 마이그레이션 후 시작", type(exc).__name__)
            time.sleep(5)
    return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    from app import telemetry
    telemetry.setup("aegismesh-worker")
    if a.once:
        print(tick())
        return

    def stop(*_):
        global _stop
        _stop = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if not wait_for_schema():
        raise SystemExit("DB 스키마 없음 — 마이그레이션 확인")
    log.warning("worker 시작 — 주기 %ss", settings.worker_interval_sec)
    while not _stop:
        try:
            tick()
        except Exception:  # noqa: BLE001 — 일시 DB 오류(local SQLite 잠김 등)로 worker 가 멈추지 않게 — 다음 주기에 다시
            log.exception("주기 실패 — 다음 주기에 다시")
        for _ in range(settings.worker_interval_sec):
            if _stop:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
