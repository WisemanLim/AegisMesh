"""재해 복구 (Epic 47 · NFR-A5 — RTO 30분 · RPO 5분 · 증적 원장 RPO 0) — 복제·WAL 보관 상태와 복구 훈련 확인.

구성(docker-compose.prod.yml): 주 서버 db 가 WAL 을 볼륨 dbbackup 에 보관(archive_timeout 마다 세그먼트 전환 = 일반 데이터 RPO 상한),
동기 대기 서버 db-standby 는 원장을 쓴 트랜잭션만 플러시까지 커밋을 기다리게 한다(app/db.py = 원장 RPO 0),
db-backup 은 주기 기본 백업(pg_basebackup). 복구 훈련은 운영 볼륨을 건드리지 않는 db-drill 에서 한다(scripts/dr_drill.sh).

  python -m app.dr status                   # 복제·보관 상태(JSON)
  python -m app.dr heads                    # 원장 체인 머리(seq·hash) — 훈련 기준점
  python -m app.dr burst N                  # 원장 N 건을 한 건씩 커밋(응답 = 동기 반영) → 마지막 머리
  python -m app.dr probe                    # 대기 서버가 멈춘 동안: 원장 커밋은 기다리고 일반 커밋은 바로 끝나는지
  python -m app.dr check --host H HEADS     # H 의 DB 로 원장 전체 검증 + 기준점 머리(JSON)가 모두 있는지
  python -m app.dr record JSON              # 훈련 결과를 원장(kind=dr)에 남긴다
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import UTC, datetime

from app.core.config import settings

TARGETS = {"rtoMin": 30, "rpoMin": 5, "ledgerRpoSec": 0}
DRILLS = ("restore-drill", "failover-drill")          # 훈련 결과 기록(ref) — burst·probe 기록은 제외


def status(s) -> dict:
    from sqlalchemy import select, text

    from app import models
    eng = s.get_bind().dialect.name
    E = models.Evidence
    drill = s.scalars(select(E).where(E.kind == "dr", E.ref_id.in_(DRILLS)).order_by(E.seq.desc()).limit(1)).first()
    last = {"at": drill.created_at, "ref": drill.ref_id, "ok": drill.body.get("ok"), "rtoSec": drill.body.get("rtoSec")} if drill else None
    if eng != "postgresql":
        return {"engine": eng, "applicable": False, "targets": TARGETS, "lastDrill": last,
                "detail": "복제·WAL 보관은 prod(PostgreSQL) 구성 — local SQLite 는 대상 아님"}
    d = s.execute(text("SELECT aegis_dr_status()")).scalar_one()
    if isinstance(d, str):
        d = json.loads(d)
    sync = [x["name"] for x in d["standbys"] if x["state"] == "streaming" and x["syncState"] in ("sync", "quorum")]
    a = d["archiver"]
    age = None
    if a.get("lastAt"):
        age = round((datetime.now(UTC) - datetime.fromisoformat(a["lastAt"])).total_seconds(), 1)
    return {"engine": eng, "applicable": True, "role": "standby" if d["inRecovery"] else "primary",
            "standbys": d["standbys"], "syncNames": d["syncNames"], "syncStandbys": sync, "ledgerRpo0": bool(sync),
            "archive": {"mode": d["archiveMode"], "timeoutSec": d["archiveTimeoutSec"], "archived": a["archived"],
                        "failed": a["failed"], "lastWal": a["lastWal"], "lastAt": a["lastAt"], "ageSec": age,
                        "lastFailedAt": a["lastFailedAt"]},
            "targets": TARGETS, "lastDrill": last}


def heads() -> dict:
    from sqlalchemy import select

    from app import db, models
    with db.system_session() as s:
        return {c.chain: {"seq": c.seq, "hash": c.hash} for c in s.scalars(select(models.LedgerChain)) if c.seq}


def burst(n: int) -> dict:
    from app import db, ledger
    for i in range(n):
        with db.system_session() as s:
            row = ledger.append(s, "dr", "burst", {"drill": "failover", "i": i}, tenant=ledger.PLATFORM)
            s.commit()                                   # 원장 트랜잭션 → 동기 대기 서버 플러시 뒤에야 응답
            last = {"seq": row.seq, "hash": row.hash}
    return {ledger.PLATFORM: last}


def probe(timeout: float = 3.0) -> dict:
    from sqlalchemy import text

    from app import db, ledger
    t0 = time.perf_counter()
    with db.system_session() as s:
        s.execute(text("SELECT pg_current_xact_id()"))   # 트랜잭션 ID 를 받아 커밋 레코드를 쓰게 한다(원장 아님)
        s.commit()
    plain = round((time.perf_counter() - t0) * 1000, 1)
    done = threading.Event()

    def write() -> None:
        with db.system_session() as s:
            ledger.append(s, "dr", "probe", {"drill": "failover", "probe": "sync-wait"}, tenant=ledger.PLATFORM)
            s.commit()
        done.set()

    threading.Thread(target=write, daemon=True).start()
    return {"plainCommitMs": plain, "ledgerCommitWaiting": not done.wait(timeout), "waitedSec": timeout}


def check(expect: dict) -> dict:
    from sqlalchemy import select, text

    from app import db, ledger, models
    with db.system_session() as s:
        t0 = time.perf_counter()
        v = ledger.verify(s)
        sec = round(time.perf_counter() - t0, 1)
        missing = [c for c, h in expect.items()
                   if s.scalar(select(models.Evidence.hash).where(models.Evidence.chain == c, models.Evidence.seq == h["seq"])) != h["hash"]]
        recovery = s.execute(text("SELECT pg_is_in_recovery()")).scalar_one() if s.get_bind().dialect.name == "postgresql" else False
    return {"ok": v["ok"] and not missing, "verify": {"ok": v["ok"], "records": v["records"], "chains": len(v["chains"]),
                                                     "detail": v["detail"], "sec": sec},
            "expectedHeads": len(expect), "missingHeads": missing, "inRecovery": recovery}


def record(body: dict) -> dict:
    from app import db, ledger
    with db.system_session() as s:
        row = ledger.append(s, "dr", body.get("drill", "drill"), body, tenant=ledger.PLATFORM)
        s.commit()
        return {"seq": row.seq, "hash": row.hash}


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--host" in args:                                  # 엔진을 만들기 전에 접속 대상만 바꾼다(계정·DB 이름은 그대로)
        i = args.index("--host")
        from sqlalchemy.engine import make_url
        settings.database_url = make_url(settings.database_url).set(host=args[i + 1]).render_as_string(hide_password=False)
        del args[i:i + 2]
    cmd = args[0] if args else "status"
    if cmd == "status":
        from app import db
        with db.system_session() as s:
            out = status(s)
    elif cmd == "heads":
        out = heads()
    elif cmd == "burst":
        out = burst(int(args[1]))
    elif cmd == "probe":
        print(json.dumps(probe(), ensure_ascii=False), flush=True)
        os._exit(0)                                       # 대기 중인 원장 커밋 스레드를 기다리지 않는다(주 서버엔 이미 로컬 커밋)
    elif cmd == "check":
        out = check(json.loads(args[1]))
    elif cmd == "record":
        out = record(json.loads(args[1]))
    else:
        raise SystemExit(__doc__)
    print(json.dumps(out, ensure_ascii=False, default=str))
    sys.exit(0 if out.get("ok", True) is not False else 1)
