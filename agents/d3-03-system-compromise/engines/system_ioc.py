"""기본 엔진: 시스템 장악 지표 — 민감 시스템 경로·권한 명령·지속성·다운로드 실행·리버스 셸 (FR-D3-03)."""
import re

from aegis.engine import Signal, walk_strings
from aegis.schemas import EvidenceItem, JudgeRequest

id = "system_ioc"

IOC = [
    ("sensitive-path", 0.93, r"(/etc/(shadow|passwd|sudoers)|~?/\.ssh/|/root/|/proc/self/environ|/var/run/docker\.sock|"
                             r"\\windows\\system32\\config\\sam|/etc/kubernetes/|\.kube/config)"),
    ("privilege-cmd", 0.92, r"(\bsudo\b|\bsu\s+-|\bchmod\s+(-R\s+)?[0-7]?777\b|\bchmod\s+[ug]?\+s\b|\bchown\s+root\b|\bsetcap\b)"),
    ("persistence", 0.9, r"(\bcrontab\b|\bsystemctl\s+enable\b|/etc/cron|\.bashrc|\.profile\b|authorized_keys|/etc/rc\.local|schtasks\s+/create)"),
    ("download-exec", 0.96, r"((curl|wget)[^|;]*\|\s*(ba|z)?sh\b|powershell(\.exe)?\s+.*-(enc|encodedcommand)\b|iex\s*\(\s*new-object)"),
    ("reverse-shell", 0.98, r"(\bnc\b.*\s-e\s|/dev/tcp/\d|bash\s+-i\s+>&|socat\s+.*exec:|python\d?\s+-c\s+.*socket.*connect)"),
    ("container-escape", 0.95, r"(--privileged|nsenter\s+--target\s+1|mount\s+.*\s/host|docker\s+run\s+.*-v\s+/:/)"),
]
RX = [(r, s, re.compile(p, re.I)) for r, s, p in IOC]


def scan(req: JudgeRequest) -> list[Signal]:
    if req.tool is None:
        return []
    out: list[Signal] = []
    for loc, v in walk_strings(req.tool.args):
        for rule, score, rx in RX:
            if (m := rx.search(v)):
                out.append(Signal(rule=rule, score=score, severity="critical", evidence=EvidenceItem(
                    kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note=f"시스템 장악 지표: {rule}")))
    return out


def explain(req: JudgeRequest) -> dict:
    hits = []
    if req.tool is not None:
        for loc, v in walk_strings(req.tool.args):
            hits += [{"arg": loc, "ioc": rule, "score": score} for rule, score, rx in RX if rx.search(v)]
    return {"kind": "ioc", "hits": hits, "note": "민감 경로·권한 명령·지속성·다운로드 실행·리버스 셸·컨테이너 탈출 지표"}
