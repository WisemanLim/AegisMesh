"""기본 엔진: 런타임 이벤트(커널 이벤트 요약) — 셸 생성·시스템 경로 쓰기·악성 연결·채굴기·무결성 (FR-D9-02).
artifact = {kind: runtime_events, host, events: [{type: exec|file_write|net_connect|integrity, process, parent, path, dest, port}]}"""
import re

from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "runtime_events"
SHELL = re.compile(r"(^|/)(sh|bash|zsh|dash|nc|ncat|socat)$")
APP = re.compile(r"(python|node|java|uvicorn|gunicorn|ruby)")
MINER = re.compile(r"(xmrig|minerd|cpuminer|kdevtmpfsi|kinsing)", re.I)
SYS_PATH = re.compile(r"^/(etc|bin|sbin|usr/bin|usr/sbin|lib|boot)/")


def scan(req: JudgeRequest):
    a = artifact_of(req, "runtime_events")
    if not a:
        return []
    out = []
    bad_ports = set(req.params.get("badPorts", [4444, 1337, 31337, 6667]))
    for i, e in enumerate(a.get("events", [])):
        loc = f"artifact.events[{i}]"
        if e.get("type") == "exec" and SHELL.search(str(e.get("process", ""))) and APP.search(str(e.get("parent", ""))):
            out.append(signal("app-spawned-shell", 0.95, "critical", loc, f"애플리케이션({e.get('parent')})이 셸 생성"))
        if e.get("type") == "exec" and MINER.search(str(e.get("process", ""))):
            out.append(signal("cryptominer", 0.97, "critical", loc, "채굴기 프로세스"))
        if e.get("type") == "file_write" and SYS_PATH.search(str(e.get("path", ""))):
            out.append(signal("system-write", 0.92, "critical", loc, f"시스템 경로 쓰기 {e.get('path')}"))
        if e.get("type") == "net_connect" and (e.get("port") in bad_ports or e.get("dest") in req.params.get("badIps", [])):
            out.append(signal("c2-connect", 0.94, "critical", loc, f"의심 목적지 연결 {e.get('dest')}:{e.get('port')}"))
        if e.get("type") == "integrity" and e.get("changed"):
            out.append(signal("integrity-change", 0.9, "high", loc, f"바이너리 무결성 변경 {e.get('path')}"))
    return out
