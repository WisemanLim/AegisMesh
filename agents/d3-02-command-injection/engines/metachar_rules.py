"""기본 엔진: 셸 메타문자·명령 치환·SQL 주입 패턴 (FR-D3-02)."""
import re

from aegis.engine import Signal, walk_strings
from aegis.schemas import EvidenceItem, JudgeRequest

id = "metachar_rules"

SHELL = re.compile(r"(;\s*\w|&&|\|\||\|\s*\w|`[^`]+`|\$\([^)]*\)|\$\{[^}]*\}|>\s*/|<\(|\n\s*\w+\s)")
SQLI = re.compile(r"('\s*(or|and)\s+'?\d*'?\s*=\s*'?\d|'\s*;\s*(drop|delete|insert|update)\b|\bunion\s+(all\s+)?select\b|--\s*$|/\*.*\*/)", re.I | re.M)
SHELLISH = re.compile(r"(shell|exec|run|command|cmd|bash|terminal|subprocess|ssh|script)", re.I)
SQLISH = re.compile(r"(sql|query|db|database|search|lookup|filter|where)", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    if t is None:
        return []
    out: list[Signal] = []
    shellish = bool(SHELLISH.search(t.name))
    for loc, v in walk_strings(t.args):
        key = loc.rsplit(".", 1)[-1]
        if (shellish or SHELLISH.search(key)) and (m := SHELL.search(v)):
            out.append(Signal(rule="shell-meta", score=0.92, severity="critical", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="셸 메타문자·명령 치환으로 추가 명령 연결")))
        elif not shellish and (m := re.search(r"`[^`]+`|\$\([^)]*\)", v)):
            out.append(Signal(rule="substitution", score=0.85, severity="high", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="일반 인자에 명령 치환 구문")))
        if (SQLISH.search(t.name) or SQLISH.search(key)) and (m := SQLI.search(v)):
            out.append(Signal(rule="sql-injection", score=0.9, severity="critical", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="SQL 주입 패턴(항진식·UNION·스택 질의)")))
    return out


def explain(req: JudgeRequest) -> dict:
    """인자별 셸 경유 여부·메타문자·명령 치환·SQL 주입 (SCR-G02 명령 주입 검사)."""
    t = req.tool
    if t is None:
        return {"kind": "injection", "args": []}
    shellish = bool(SHELLISH.search(t.name))
    rows = []
    for loc, v in walk_strings(t.args):
        key = loc.rsplit(".", 1)[-1]
        rows.append({"arg": loc, "shellContext": shellish or bool(SHELLISH.search(key)), "shellMeta": bool(SHELL.search(v)),
                     "substitution": bool(re.search(r"`[^`]+`|\$\([^)]*\)", v)), "sqlContext": bool(SQLISH.search(t.name) or SQLISH.search(key)),
                     "sqlInjection": bool(SQLI.search(v))})
    return {"kind": "injection", "tool": t.name, "shellTool": shellish, "args": rows,
            "note": "셸 미경유 실행(인자 배열)·인자 허용목록이 기본. 메타문자·명령 치환·SQL 주입 패턴은 실행 전 정적 검사로 차단"}
