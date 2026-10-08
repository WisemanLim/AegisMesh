"""기본 엔진: 도구 요구 권한 범위 대 주체 권한 + 권한 변경 인자 (FR-D3-06)."""
import re

from aegis.engine import Signal, walk_strings
from aegis.schemas import EvidenceItem, JudgeRequest

id = "scope_check"

GRANT_TOOL = re.compile(r"(grant|role|permission|privilege|group|acl|iam|policy|sudoers|admin)", re.I)
ELEVATE = re.compile(r"\b(admin(istrator)?|root|owner|superuser|sudo|full[_-]?access|all[_-]?permissions)\b|^\*(:\*)?$", re.I)


def _effective_scopes(req: JudgeRequest) -> set[str] | None:
    """대리 실행이면 사람·에이전트 권한의 교집합(혼동된 대리인 방지)."""
    sub = req.subject
    if sub.principal is None:
        return None
    scopes = set(sub.principal.scopes)
    if sub.on_behalf_of is not None:
        scopes &= set(sub.on_behalf_of.scopes)
    return scopes


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    if t is None:
        return []
    out: list[Signal] = []
    have = _effective_scopes(req)
    if t.required_scopes:
        missing = sorted(set(t.required_scopes) - (have or set()))
        if missing:
            out.append(Signal(rule="scope-exceeded", score=0.94, severity="critical", evidence=EvidenceItem(
                kind="scope", location="tool.requiredScopes", note=f"주체 권한에 없는 범위: {', '.join(missing)}")))
    prior = [str(h.get("tool")) for h in req.history if h.get("tool")]
    for chain in req.params.get("blockedChains", []):
        a, _, b = str(chain).partition("->")
        if b and t.name == b.strip() and a.strip() in prior:
            out.append(Signal(rule="blocked-chain", score=0.9, severity="high", evidence=EvidenceItem(
                kind="chain", location="history", note=f"차단된 상승 경로 {a.strip()} → {b.strip()}")))
    if GRANT_TOOL.search(t.name):
        roles = set(req.subject.principal.roles) if req.subject.principal else set()
        for loc, v in walk_strings(t.args):
            if ELEVATE.search(v) or (isinstance(v, str) and v.lower() in ("true",) and "admin" in loc.lower()):
                is_admin = bool(roles & {"admin", "security-admin", "iam-admin"})
                out.append(Signal(rule="self-elevation" if not is_admin else "privilege-change",
                                  score=0.92 if not is_admin else 0.8, severity="critical" if not is_admin else "high",
                                  evidence=EvidenceItem(kind="span", location=loc,
                                                        note=("관리자 역할 없는 주체의 권한 상승 시도" if not is_admin
                                                              else "관리자 권한 부여 — 2인 승인 대상"))))
                break
    return out


SECRETISH = re.compile(r"(secret|credential|token|password|key|vault|kms)", re.I)
READISH = re.compile(r"(read|list|get|search|files?|fs|browse)", re.I)


def escalation_paths(tools: list[str]) -> list[dict]:
    """도구 이름 조합의 잠재 권한 상승 경로(정적) — 읽기·탐색 도구 → 비밀·권한 변경 도구 (SCR-G04)."""
    out = []
    for a in tools:
        for b in tools:
            if a == b:
                continue
            if READISH.search(a) and (SECRETISH.search(b) or GRANT_TOOL.search(b)):
                out.append({"from": a, "to": b, "risk": "high" if GRANT_TOOL.search(b) else "medium",
                            "why": "권한 변경 도구" if GRANT_TOOL.search(b) else "비밀 접근 도구"})
    return out


def explain(req: JudgeRequest) -> dict:
    """유효 권한(대리 실행 = 교집합)·요구 범위·다운스코핑 결과·차단 경로 (SCR-G04)."""
    t, sub = req.tool, req.subject
    have = _effective_scopes(req)
    need = sorted(t.required_scopes) if t else []
    return {"kind": "scopes", "tool": t.name if t else None, "principalScopes": sorted(sub.principal.scopes) if sub.principal else [],
            "agentScopes": sorted(sub.on_behalf_of.scopes) if sub.on_behalf_of else None,
            "effective": sorted(have) if have is not None else None, "required": need,
            "downscoped": sorted(set(need) & (have or set())), "missing": sorted(set(need) - (have or set())),
            "history": [str(h.get("tool")) for h in req.history if h.get("tool")], "blockedChains": req.params.get("blockedChains", [])}
