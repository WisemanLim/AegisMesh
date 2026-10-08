"""발견 버스 (Epic 60 · PRD 전용 인프라 NATS) — 원장(추가 전용·단조 seq)을 커서로 읽어 발견·사건·인증 보안 이벤트를 NATS JetStream 에 게시한다.

- 최소 1회: 게시 → JetStream 확인(ack) → 커서 전진. 같은 원장 ID 를 `Nats-Msg-Id` 로 실어 중복 창(2분) 안 재전송은 스트림이 버린다.
- 주제: aegis.findings.<tenant>.<verdict> · aegis.incidents.<tenant> · aegis.auth.<tenant>. 페이로드는 요약만(입력 원문·근거 메모 없음, NFR-D1).
- 스트림 AEGIS(파일 저장, 보존 BUS_MAX_AGE_DAYS) — 소비자(SIEM 등)는 지속 소비자로 처음부터 재생할 수 있다.
- 표준 라이브러리 NATS 클라이언트(TCP·선택 TLS, PUB/HPUB/SUB/MSG/HMSG/PING). prod 는 상호 TLS(내부 CA).

  python -m app.bus relay                       # compose 서비스 bus-relay
  python -m app.bus tail [DURABLE] [--max N]    # SIEM 소비 예 — 지속 소비자로 받아 출력·확인(ack)
"""
from __future__ import annotations

import json
import secrets
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import db, models
from app.core.config import settings

KINDS = ("finding", "incident", "auth")
AUTH_EVENTS = {"session_anomaly", "impossible_travel", "token_replay", "mfa_rejected", "locked", "break_glass_login"}


class BusError(Exception):
    pass


class Nats:
    """최소 동기 NATS 클라이언트 — 요청/응답(JetStream API·게시 확인)용 받은편지함 하나."""

    def __init__(self, url: str, timeout: float = 5.0):
        u = urlparse(url)
        self.timeout, self.inbox, self.n = timeout, f"_INBOX.{secrets.token_hex(8)}", 0
        sock = socket.create_connection((u.hostname, u.port or 4222), timeout=timeout)
        self.f = sock.makefile("rb")
        info = self._line()
        if not info.startswith(b"INFO "):
            raise BusError(f"NATS 인사 없음: {info[:60]!r}")
        if u.scheme == "tls" or json.loads(info[5:]).get("tls_required"):
            c = ssl.create_default_context(cafile=settings.bus_ca_file or None)
            if settings.bus_client_cert:
                c.load_cert_chain(settings.bus_client_cert, settings.bus_client_key or None)
            sock = c.wrap_socket(sock, server_hostname=u.hostname)
            self.f = sock.makefile("rb")
        self.sock = sock
        self._send(b'CONNECT {"verbose":false,"pedantic":false,"name":"aegismesh","lang":"python","version":"1","protocol":1,'
                   b'"headers":true,"no_responders":true}\r\nPING\r\n' + f"SUB {self.inbox}.* 1\r\n".encode())
        while (line := self._line()) != b"PONG":
            if line.startswith(b"-ERR"):
                raise BusError(line.decode(errors="replace"))

    def _send(self, b: bytes) -> None:
        self.sock.sendall(b)

    def _line(self) -> bytes:
        line = self.f.readline()
        if not line:
            raise BusError("NATS 연결 끊김")
        return line.rstrip(b"\r\n")

    def _read_msg(self, deadline: float) -> tuple[str, str | None, dict, bytes]:
        """다음 MSG/HMSG → (주제, 응답 주제, 헤더, 본문). PING 은 PONG 으로."""
        while True:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            line = self._line()
            if line == b"PING":
                self._send(b"PONG\r\n")
                continue
            if line.startswith(b"-ERR"):
                raise BusError(line.decode(errors="replace"))
            parts = line.split()
            if parts[0] == b"MSG":
                subj, reply, n = parts[1].decode(), (parts[3].decode() if len(parts) == 5 else None), int(parts[-1])
                data = self.f.read(n + 2)[:-2]
                return subj, reply, {}, data
            if parts[0] == b"HMSG":
                subj, reply = parts[1].decode(), (parts[3].decode() if len(parts) == 6 else None)
                hl, tl = int(parts[-2]), int(parts[-1])
                raw = self.f.read(tl + 2)[:-2]
                head = raw[:hl].decode(errors="replace").split("\r\n")
                hdr = {"_status": head[0][9:].strip()} | {k.strip(): v.strip() for k, v in (h.split(":", 1) for h in head[1:] if ":" in h)}
                return subj, reply, hdr, raw[hl:]

    def publish(self, subject: str, data: bytes, headers: dict | None = None, reply: str | None = None) -> None:
        r = f" {reply}" if reply else ""
        if headers:
            h = ("NATS/1.0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode()
            self._send(f"HPUB {subject}{r} {len(h)} {len(h) + len(data)}\r\n".encode() + h + data + b"\r\n")
        else:
            self._send(f"PUB {subject}{r} {len(data)}\r\n".encode() + data + b"\r\n")

    def request(self, subject: str, data: bytes = b"", headers: dict | None = None, timeout: float | None = None) -> dict:
        self.n += 1
        reply = f"{self.inbox}.{self.n}"
        self.publish(subject, data, headers, reply)
        deadline = time.time() + (timeout or self.timeout)
        while True:
            subj, _, hdr, body = self._read_msg(deadline)
            if subj != reply:
                continue                                                 # 늦게 온 다른 응답
            if hdr.get("_status", "").startswith("503"):
                raise BusError(f"응답자 없음(JetStream 꺼짐?) — {subject}")
            return json.loads(body or b"{}")

    def fetch(self, stream: str, durable: str, batch: int, wait: float = 1.0) -> list[tuple[str, str, bytes]]:
        """지속 소비자에서 묶음 가져오기 → [(주제, 확인 주제, 본문)]."""
        self.n += 1
        reply = f"{self.inbox}.{self.n}"
        self.publish(f"$JS.API.CONSUMER.MSG.NEXT.{stream}.{durable}",
                     json.dumps({"batch": batch, "expires": int(wait * 1e9)}).encode(), reply=reply)
        out, deadline = [], time.time() + wait + 2
        while len(out) < batch:
            try:
                subj, ack, hdr, body = self._read_msg(deadline)
            except (TimeoutError, socket.timeout):
                break
            if subj == reply and hdr.get("_status", "")[:3] in ("404", "408", "409"):
                break                                                    # 더 없음·만료
            if ack and ack.startswith("$JS.ACK."):
                out.append((subj, ack, body))
        return out

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def ensure_stream(nc: Nats) -> dict:
    name = settings.bus_stream
    info = nc.request(f"$JS.API.STREAM.INFO.{name}")
    if "error" not in info:
        return info
    cfg = {"name": name, "subjects": ["aegis.>"], "retention": "limits", "storage": "file", "num_replicas": 1,
           "max_age": int(settings.bus_max_age_days * 86400 * 1e9), "duplicate_window": int(120 * 1e9), "discard": "old"}
    r = nc.request(f"$JS.API.STREAM.CREATE.{name}", json.dumps(cfg).encode())
    if "error" in r:
        raise BusError(f"스트림 만들기 실패 — {r['error']}")
    return r


def message(e: models.Evidence) -> tuple[str, dict] | None:
    """원장 기록 → (주제, 요약) — 버스에 내보내지 않을 기록이면 None."""
    b, t = e.body or {}, e.tenant or "platform"
    base = {"ledgerSeq": e.seq, "ledgerId": e.id, "tenant": t, "at": e.created_at}
    if e.kind == "finding":
        v = b.get("effectiveVerdict") or b.get("verdict")
        if v in (None, "allow"):
            return None
        a = b.get("agent") or {}
        return f"aegis.findings.{t}.{v}", base | {"finding": b.get("id"), "traceId": b.get("traceId"), "agent": a.get("id"),
                                                   "ruleId": b.get("ruleId"), "verdict": b.get("verdict"), "effectiveVerdict": v,
                                                   "severity": b.get("severity"), "gate": b.get("gate"), "confidence": b.get("confidence"),
                                                   "standards": sorted((b.get("standards") or {}).keys())}
    if e.kind == "incident":
        return f"aegis.incidents.{t}", base | {"incident": e.ref_id, "event": b.get("event"), "domain": b.get("domain"),
                                               "severity": b.get("severity"), "rules": b.get("rules"), "findings": b.get("findings")}
    if e.kind == "auth" and b.get("event") in AUTH_EVENTS:
        return f"aegis.auth.{t}", base | {"event": b.get("event"), "session": b.get("session"), "verdict": b.get("verdict"),
                                          "reason": b.get("reason") if b.get("event") != "break_glass_login" else None}
    return None


def _cursor(s: Session) -> models.BusCursor:
    c = s.get(models.BusCursor, "relay")
    if c is None:
        start = 0 if settings.bus_start == "all" else (s.scalar(select(func.max(models.Evidence.seq))) or 0)
        c = models.BusCursor(name="relay", seq=start)
        s.add(c)
        s.commit()
    return c


def relay_once(s: Session, nc: Nats, batch: int = 2000) -> dict:
    """커서 다음부터 대상 종류 기록을 게시하고, 모두 확인되면 커서를 옮긴다."""
    db.set_scope(s, "*")
    c = _cursor(s)
    head = s.scalar(select(func.max(models.Evidence.seq))) or 0
    rows = list(s.scalars(select(models.Evidence).where(models.Evidence.seq > c.seq, models.Evidence.seq <= head,
                                                        models.Evidence.kind.in_(KINDS)).order_by(models.Evidence.seq).limit(batch)))
    sent = dup = 0
    for e in rows:
        m = message(e)
        if m is None:
            continue
        r = nc.request(m[0], json.dumps(m[1], ensure_ascii=False, default=str).encode(), {"Nats-Msg-Id": e.id})
        if "error" in r:
            raise BusError(f"게시 실패 seq {e.seq} — {r['error']}")
        sent, dup = sent + 1, dup + bool(r.get("duplicate"))
    c.seq = rows[-1].seq if len(rows) == batch else head                # 묶음이 찼으면 거기까지, 아니면 머리까지(대상 없는 구간 건너뜀)
    s.commit()
    return {"published": sent, "duplicates": dup, "cursor": c.seq, "head": head}


def status(s: Session) -> dict:
    c = s.get(models.BusCursor, "relay")
    head = s.scalar(select(func.max(models.Evidence.seq))) or 0
    out = {"enabled": bool(settings.bus_url), "url": settings.bus_url or None, "stream": settings.bus_stream,
           "cursor": c.seq if c else None, "head": head, "lag": (head - c.seq) if c else None}
    if settings.bus_url:
        try:
            nc = Nats(settings.bus_url, 3)
            st = nc.request(f"$JS.API.STREAM.INFO.{settings.bus_stream}").get("state") or {}
            nc.close()
            out |= {"ok": True, "messages": st.get("messages"), "firstSeq": st.get("first_seq"), "lastSeq": st.get("last_seq"),
                    "consumers": st.get("consumer_count")}
        except (OSError, BusError, ValueError) as e:
            out |= {"ok": False, "error": str(e)[:200]}
    return out


def relay() -> None:
    while True:
        try:
            nc = Nats(settings.bus_url)
            ensure_stream(nc)
            while True:
                with db.system_session() as s:
                    r = relay_once(s, nc)
                if r["published"]:
                    print(json.dumps(r), flush=True)
                if r["cursor"] >= r["head"]:
                    time.sleep(settings.bus_poll_sec)                    # 따라잡았을 때만 쉰다
        except Exception as e:  # noqa: BLE001 — NATS·DB·KMS 장애: 커서는 확인된 곳까지만 전진했다. 기록하고 다시
            print(json.dumps({"error": str(e)[:200]}), flush=True)
            time.sleep(3)


def tail(durable: str = "siem", max_msgs: int = 0) -> None:
    nc = Nats(settings.bus_url)
    ensure_stream(nc)
    r = nc.request(f"$JS.API.CONSUMER.CREATE.{settings.bus_stream}.{durable}", json.dumps(
        {"stream_name": settings.bus_stream, "config": {"name": durable, "durable_name": durable, "ack_policy": "explicit",
                                                        "deliver_policy": "all", "filter_subject": "aegis.>", "ack_wait": int(30e9)}}).encode())
    if "error" in r and r["error"].get("err_code") != 10148:            # 같은 설정으로 이미 있음
        raise BusError(f"소비자 만들기 실패 — {r['error']}")
    got = 0
    while not max_msgs or got < max_msgs:
        msgs = nc.fetch(settings.bus_stream, durable, min(100, (max_msgs - got) if max_msgs else 100))
        if not msgs and max_msgs:
            break
        for subj, ack, body in msgs:
            print(json.dumps({"subject": subj} | json.loads(body), ensure_ascii=False), flush=True)
            nc.publish(ack, b"+ACK")
            got += 1
    nc.close()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "relay":
        relay()
    elif len(sys.argv) >= 2 and sys.argv[1] == "tail":
        args = sys.argv[2:]
        n = int(args[args.index("--max") + 1]) if "--max" in args else 0
        tail(next((a for a in args if not a.startswith("--") and a != str(n)), "siem"), n)
    elif len(sys.argv) >= 2 and sys.argv[1] == "status":
        with db.system_session() as s:
            print(json.dumps(status(s)))
    else:
        raise SystemExit(__doc__)
