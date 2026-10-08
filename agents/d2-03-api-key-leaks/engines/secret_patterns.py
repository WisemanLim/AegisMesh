"""기본 엔진: 자격증명 패턴 사전 (FR-D2-03). 값은 증거에 남기지 않고 위치·유형만 기록한다."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "secret_patterns"

PATTERNS: list[tuple[str, str, float, re.Pattern]] = [
    ("anthropic-key", "critical", 0.99, re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", "critical", 0.97, re.compile(r"sk-(proj-)?[A-Za-z0-9_\-]{20,}")),
    ("aws-access-key", "critical", 0.97, re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "critical", 0.97, re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("slack-token", "high", 0.95, re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", "high", 0.95, re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("private-key", "critical", 0.99, re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", "high", 0.85, re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("conn-string", "high", 0.9, re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^\s:/]+:[^\s@/]+@")),
]


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    seen: set[tuple[str, int]] = set()
    for loc, text in req.texts("output", "text", "segments"):
        for rule, sev, score, rx in PATTERNS:
            for m in rx.finditer(text):
                if (loc, m.start()) in seen:   # sk-ant 와 sk- 중복 방지
                    continue
                seen.add((loc, m.start()))
                out.append(Signal(rule=rule, score=score, severity=sev, evidence=EvidenceItem(
                    kind="span", location=loc, offset=m.start(), length=m.end() - m.start(),
                    note=f"{rule} 형태 자격증명 (값은 기록하지 않음)")))
    return out
