"""worker 주기 — 한 주기의 예외(local SQLite 잠김 등)가 worker 를 멈추지 않는다(10차 게이트에서 발견)."""
import sys

from sqlalchemy.exc import OperationalError

from app import telemetry, worker
from app.core.config import settings


def test_loop_survives_a_failing_tick(monkeypatch):
    calls = []

    def tick():
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("SELECT scan_targets", {}, Exception("database is locked"))
        worker._stop = True
        return []
    monkeypatch.setattr(worker, "tick", tick)
    monkeypatch.setattr(worker, "wait_for_schema", lambda: True)
    monkeypatch.setattr(telemetry, "setup", lambda name: False)
    monkeypatch.setattr(settings, "worker_interval_sec", 0)
    monkeypatch.setattr(sys, "argv", ["worker"])
    monkeypatch.setattr(worker, "_stop", False)
    worker.main()
    assert len(calls) == 2
