"""Epic 60 — 발견 버스: 원장 → 메시지 요약(원문·근거 메모 없음), 커서는 확인 받은 곳까지만, 중복 표시, 최소 NATS 클라이언트(가짜 서버)."""
import json
import socket
import threading

import pytest
from sqlalchemy import func, select

from app import bus, db, ledger, models
from app.core.config import settings


class FakeJS:
    def __init__(self, fail_at=None):
        self.sent, self.fail_at, self.seen = [], fail_at, set()

    def request(self, subject, data=b"", headers=None, timeout=None):
        if self.fail_at is not None and len(self.sent) == self.fail_at:
            raise bus.BusError("connection reset")
        mid = (headers or {}).get("Nats-Msg-Id")
        dup = mid in self.seen
        self.seen.add(mid)
        self.sent.append((subject, json.loads(data), mid))
        return {"stream": "AEGIS", "seq": len(self.sent), "duplicate": dup}


def _seed(s):
    f = {"schema": "aegismesh.io/Finding/v1", "id": "fnd_bus1", "traceId": "t1", "agent": {"id": "d1-01"}, "ruleId": "D1-01.override",
         "verdict": "block", "effectiveVerdict": "block", "severity": "high", "gate": "input", "standards": {"owasp-llm": {}},
         "evidence": [{"kind": "text", "note": "SECRET-INPUT-FRAGMENT"}]}
    ledger.append(s, "finding", "fnd_bus1", f, "default")
    ledger.append(s, "finding", "fnd_bus2", f | {"id": "fnd_bus2", "verdict": "allow", "effectiveVerdict": "allow"}, "default")
    ledger.append(s, "incident", "inc_bus1", {"event": "opened", "domain": "D1", "severity": "high", "rules": ["D1-01.override"], "findings": ["fnd_bus1"]}, "default")
    ledger.append(s, "auth", "u1", {"event": "impossible_travel", "user": "kim", "session": "s1", "verdict": "alert", "reason": "✈ KR → US"}, "default")
    ledger.append(s, "auth", "u1", {"event": "login", "user": "kim"}, "default")
    s.commit()


def test_relay_publishes_summaries_and_advances_cursor_only_after_ack(migrated, monkeypatch):
    monkeypatch.setattr(settings, "bus_start", "head")
    with db.system_session() as s:
        db.set_scope(s, "*")
        s.query(models.BusCursor).delete()
        s.commit()
        bus._cursor(s)                                                         # 지금 머리부터
        _seed(s)
        head = s.scalar(select(func.max(models.Evidence.seq)))
        broken = FakeJS(fail_at=1)
        with pytest.raises(bus.BusError):
            bus.relay_once(s, broken)
        s.rollback()
        assert s.get(models.BusCursor, "relay").seq < head                     # 확인 못 받은 구간은 다시
        js = FakeJS()
        js.seen = broken.seen
        r = bus.relay_once(s, js)
    assert r["cursor"] == head and r["published"] == 3 and r["duplicates"] == 1           # 앞서 보낸 1건은 스트림이 중복으로 표시
    subjects = [x[0] for x in js.sent]
    assert subjects == ["aegis.findings.default.block", "aegis.incidents.default", "aegis.auth.default"]
    body = json.dumps([x[1] for x in js.sent], ensure_ascii=False)
    assert "SECRET-INPUT-FRAGMENT" not in body and '"user"' not in body and js.sent[0][1]["ruleId"] == "D1-01.override"
    assert all(x[2].startswith("evd_") for x in js.sent)                                  # Nats-Msg-Id = 원장 ID


def _fake_server(script):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = []

    def run():
        c, _ = srv.accept()
        f = c.makefile("rb")
        c.sendall(b'INFO {"server_id":"x","headers":true,"jetstream":true}\r\n')
        for expect, reply in script:
            buf = b""
            while expect not in buf:
                buf += f.readline()
            got.append(buf)
            if reply:
                c.sendall(reply)
        c.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], got


def test_minimal_client_protocol():
    port, got = _fake_server([(b"PING", b"PONG\r\n"), (b"Nats-Msg-Id: evd_1", b"PING\r\nMSG _INBOX.REPLACE 1 26\r\n" + b'{"stream":"AEGIS","seq":7}' + b"\r\n")])
    nc = bus.Nats(f"nats://127.0.0.1:{port}")                                   # 받은편지함 이름은 무작위 — 응답 주제를 고쳐 끼운다
    nc.n = 0
    orig = nc._read_msg

    def patched(deadline):
        subj, reply, hdr, body = orig(deadline)
        return (f"{nc.inbox}.1" if subj == "_INBOX.REPLACE" else subj), reply, hdr, body
    nc._read_msg = patched
    r = nc.request("aegis.x", b"{}", {"Nats-Msg-Id": "evd_1"})
    assert r == {"stream": "AEGIS", "seq": 7}
    assert b'"headers":true' in got[0] and b"SUB _INBOX." in got[1]
    assert b"Nats-Msg-Id: evd_1" in got[1] and b"HPUB aegis.x _INBOX." in got[1]
    nc.close()
