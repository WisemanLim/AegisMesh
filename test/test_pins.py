"""Epic 58 — 고정 판 갱신: 다음 판 정하기(DB-IP 이번 달·지난달, MDS3 nextUpdate), Dockerfile 전역 ARG 고쳐 쓰기, MDS 캐시 판 일치,
실행 중 낡음 점검 → worker 원장 → 알림."""
import base64
import json
from datetime import date

import pytest

from app import fido, geo, pins, worker
from scripts import fetch_mds
from scripts import pins as pinscript


def _mds_dir(tmp_path, next_update):
    d = tmp_path / "fido"
    d.mkdir()
    body = base64.urlsafe_b64encode(json.dumps({"no": 290, "nextUpdate": next_update}).encode()).decode().rstrip("=")
    (d / "blob.jwt").write_text(f"h.{body}.s")
    return d


def test_resolve_picks_next_dbip_month_and_mds_label(tmp_path, monkeypatch):
    got = []
    monkeypatch.setattr(pinscript, "_sha256", lambda url: got.append(url) or ("b" * 64 if "2026-10" in url else None))
    monkeypatch.setenv("FIDO_MDS_DIR", str(_mds_dir(tmp_path, "2026-11-01")))
    monkeypatch.setenv("DBIP_MONTH", "2026-09")
    monkeypatch.setenv("DBIP_SHA256", "a" * 64)
    monkeypatch.setenv("FIDO_MDS_SNAPSHOT", "2026-10")
    r = pinscript.resolve(str(tmp_path / "p.json"), date(2026, 10, 15))
    assert r["pins"] == {"DBIP_MONTH": "2026-10", "DBIP_SHA256": "b" * 64, "FIDO_MDS_SNAPSHOT": "2026-10"} and r["changed"] == ["DBIP_MONTH", "DBIP_SHA256"]
    got.clear()
    monkeypatch.setenv("DBIP_MONTH", "2026-10")
    monkeypatch.setenv("DBIP_SHA256", "b" * 64)
    r = pinscript.resolve(str(tmp_path / "p.json"), date(2026, 11, 2))               # 11월 판 아직 없음 → 10월 = 지금 판, MDS 는 다음 갱신 지남
    assert got == ["https://download.db-ip.com/free/dbip-city-lite-2026-11.mmdb.gz"]   # 지금 판은 다시 받지 않는다
    assert r["pins"]["DBIP_MONTH"] == "2026-10" and r["pins"]["FIDO_MDS_SNAPSHOT"] == "2026-11" and r["changed"] == ["FIDO_MDS_SNAPSHOT"]


def test_apply_rewrites_only_the_global_args(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("# x\nARG DBIP_MONTH=2026-09\nARG DBIP_SHA256=" + "a" * 64 + "\nARG FIDO_MDS_SNAPSHOT=2026-09\nFROM scratch AS s\nARG DBIP_MONTH\n")
    src = tmp_path / "p.json"
    src.write_text(json.dumps({"pins": {"DBIP_MONTH": "2026-10", "DBIP_SHA256": "c" * 64, "FIDO_MDS_SNAPSHOT": "2026-10"}}))
    assert pinscript.apply(str(src), str(df)) == ["DBIP_MONTH", "DBIP_SHA256", "FIDO_MDS_SNAPSHOT"]
    text = df.read_text()
    assert "ARG DBIP_MONTH=2026-10\n" in text and "ARG DBIP_SHA256=" + "c" * 64 in text and text.endswith("ARG DBIP_MONTH\n")   # 스테이지 안 선언은 그대로
    src.write_text(json.dumps({"pins": {"DBIP_MONTH": "2026-10; rm", "DBIP_SHA256": "c" * 64, "FIDO_MDS_SNAPSHOT": "2026-10"}}))
    with pytest.raises(SystemExit, match="형식 오류"):
        pinscript.apply(str(src), str(df))


def test_mds_cache_reused_only_for_the_same_snapshot():
    assert fetch_mds._same_snapshot({"snapshot": "2026-10", "fetchedAt": "2026-10-08T00:55:49+00:00"}, "2026-10")
    assert not fetch_mds._same_snapshot({"snapshot": "2026-10", "fetchedAt": "2026-10-08T00:55:49+00:00"}, "2026-11")
    assert fetch_mds._same_snapshot({"fetchedAt": "2026-10-08T00:55:49+00:00"}, "2026-10")          # 판 이름 없는 옛 사본 = 받은 달
    assert fetch_mds._same_snapshot({"fetchedAt": "2026-10-08T00:55:49+00:00"}, "")


def test_stale_check_records_and_notifies(monkeypatch, client):
    monkeypatch.setattr(fido, "status", lambda: {"loaded": True, "no": 290, "nextUpdate": "2026-11-01", "stale": True, "fetchedAt": "2026-10-08"})
    monkeypatch.setattr(geo, "status", lambda: {"loaded": True, "month": "2026-10", "built": "2026-10-01", "error": None})
    r = pins.check(date(2026, 11, 20))
    assert r["stale"] == ["fido-mds3", "dbip-city-lite"] and r["items"][1]["ageDays"] == 50
    assert pins.check(date(2026, 10, 20))["items"][1]["stale"] is False
    monkeypatch.setattr(pins, "check", lambda today=None: r)
    monkeypatch.setattr(worker, "_due", lambda s, kind, interval: kind == "pins")
    monkeypatch.setattr(worker, "_due_quality", lambda s, ref, interval: False)
    from app import db
    with db.system_session() as s:
        assert {"job": "pins", "stale": ["fido-mds3", "dbip-city-lite"]} in worker.scheduled(s)
    notes = [n for n in client.get("/v1/notifications").json()["items"] if n["kind"] == "고정 판"]
    assert len(notes) == 2 and "make pins-refresh" in notes[0]["text"] and notes[0]["href"] == "/admin/updates"
    assert client.get("/v1/updates").json()["pins"]["stale"] == ["fido-mds3", "dbip-city-lite"]
