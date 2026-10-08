"""Epic 47 — 재해 복구 (NFR-A5): 상태 API · 훈련 기준점/검증/기록 · prod 구성(WAL 보관·동기 대기·백업·훈련) 고정.

실제 복제·WAL 재생·승격·RTO 측정은 prod 리허설(`make db-restore-drill` / `make db-failover-drill CONFIRM=1` ENV=prod)에서 한다.
"""
from pathlib import Path

import yaml

from app import db, dr, ledger

ROOT = Path(__file__).resolve().parent.parent


def test_status_api_on_sqlite_is_not_applicable(client):
    r = client.get("/v1/observability/dr")
    assert r.status_code == 200
    d = r.json()
    assert d["applicable"] is False and d["engine"] == "sqlite"
    assert d["targets"] == {"rtoMin": 30, "rpoMin": 5, "ledgerRpoSec": 0}


def test_heads_check_and_record(client):
    with db.system_session() as s:
        ledger.append(s, "dr", "unit", {"drill": "unit"}, tenant=ledger.PLATFORM)
        s.commit()
    heads = dr.heads()
    assert heads[ledger.PLATFORM]["seq"] > 0
    out = dr.check(heads)
    assert out["ok"] and out["missingHeads"] == [] and out["verify"]["ok"] and out["inRecovery"] is False
    bad = {ledger.PLATFORM: {"seq": heads[ledger.PLATFORM]["seq"], "hash": "0" * 64}}
    assert dr.check(bad)["missingHeads"] == [ledger.PLATFORM] and dr.check(bad)["ok"] is False   # 기준점 머리가 없으면 실패
    ack = dr.burst(3)                                                                              # 장애 조치 훈련의 응답 머리
    assert ack[ledger.PLATFORM]["seq"] == heads[ledger.PLATFORM]["seq"] + 3 and dr.check(ack)["ok"]
    rec = dr.record({"drill": "restore-drill", "ok": True, "rtoSec": 42})
    dr.burst(1)                                                                                    # 훈련 중간 기록은 '최근 훈련'이 아니다
    assert rec["seq"] > heads[ledger.PLATFORM]["seq"]
    last = client.get("/v1/observability/dr").json()["lastDrill"]
    assert last["ref"] == "restore-drill" and last["ok"] is True and last["rtoSec"] == 42


def test_prod_compose_wires_archive_sync_standby_backup_and_drill():
    c = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())["services"]
    cmd = " ".join(c["db"]["command"])
    for flag in ("archive_mode=on", "archive_timeout=${DB_ARCHIVE_TIMEOUT_SEC:-60}", "synchronous_commit=local", "hba_file=/aegis-pg/pg_hba.conf"):
        assert flag in cmd
    assert c["db-standby"]["init"] is True and "dbbackup:/backup:ro" in c["db-standby"]["volumes"]
    assert c["db-backup"]["entrypoint"][-1] == "loop"
    assert c["db-drill"]["profiles"] == ["drill"] and not any(isinstance(v, str) and v.startswith("dbdata:") for v in c["db-drill"]["volumes"])   # 운영 볼륨 무변경
