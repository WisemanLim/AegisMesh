"""기본 엔진: 도구 허용목록 + 코드 실행 도구 승인 여부 (FR-D3-07)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "exec_allowlist"

CODE_EXEC = re.compile(r"^(exec|eval|execute|shell|bash|sh|zsh|python\d?|node|repl|jupyter|code_?interpreter)$"
                       r"|^(run|exec|execute)_?(code|python|script|shell|command|cmd|js|bash)(_|$)"
                       r"|^subprocess|^spawn_?(process|shell)", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    if t is None:
        return []
    out: list[Signal] = []
    allow = req.params.get("toolAllowlist")
    if allow is not None and t.name not in allow:
        out.append(Signal(rule="not-allowlisted", score=0.96, severity="critical", evidence=EvidenceItem(
            kind="tool", location="tool.name", note=f"허용목록에 없는 도구 '{t.name}'")))
    if CODE_EXEC.search(t.name) and not t.approved:
        out.append(Signal(rule="code-exec", score=0.85, severity="high", evidence=EvidenceItem(
            kind="tool", location="tool.name", note=f"코드 실행 도구 '{t.name}' — 격리 L2 이상 + 승인 필요")))
    return out


def explain(req: JudgeRequest) -> dict:
    t = req.tool
    allow = req.params.get("toolAllowlist")
    return {"kind": "registry", "tool": t.name if t else None, "allowlist": allow,
            "allowlisted": None if allow is None or t is None else t.name in allow,
            "codeExec": bool(t and CODE_EXEC.search(t.name)), "approved": bool(t and t.approved)}
