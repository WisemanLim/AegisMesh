"""기본 엔진: 하위 시스템(sink)별 출력 위험 — HTML(XSS)·SQL·셸 (FR-X05, LLM10).
params.downstream: html(기본) | sql | shell | markdown."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "sink_rules"

XSS = re.compile(r"(<\s*script\b|<\s*iframe\b|<\s*object\b|<\s*embed\b|\bon(error|load|click|mouseover|focus)\s*=|"
                 r"javascript\s*:|<\s*svg[^>]*\bon\w+\s*=|<\s*meta[^>]+http-equiv\s*=\s*[\"']?refresh)", re.I)
SQL_MULTI = re.compile(r";\s*(drop|delete|update|insert|alter|truncate|grant|create)\b", re.I)
SQL_DESTRUCT = re.compile(r"^\s*(drop|truncate|alter|grant|delete\s+from\s+\w+\s*;?\s*$)", re.I | re.M)
SHELL = re.compile(r"(;|&&|\|\||\||`|\$\(|>\s*/|\brm\s+-rf\b|\bcurl\b[^|]*\|\s*sh)")


def scan(req: JudgeRequest) -> list[Signal]:
    text = req.output or ""
    sink = req.params.get("downstream", "html")
    out: list[Signal] = []
    if sink in ("html", "markdown"):
        for m in XSS.finditer(text):
            out.append(Signal(rule="xss", score=0.92, severity="high", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note="실행 가능한 HTML·스크립트")))
            break
    elif sink == "sql":
        if (m := SQL_MULTI.search(text) or SQL_DESTRUCT.search(text)):
            out.append(Signal(rule="sql-sink", score=0.93, severity="critical", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note="SQL 실행 대상 출력에 다중·파괴 구문")))
    elif sink == "shell":
        if (m := SHELL.search(text)):
            out.append(Signal(rule="shell-sink", score=0.93, severity="critical", evidence=EvidenceItem(
                kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note="셸 실행 대상 출력에 연결·치환·파괴 구문")))
    return out
