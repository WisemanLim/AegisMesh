"""기본 엔진: 서드파티 MCP 서버·플러그인·스킬 심사 (FR-D7-01) — 서명·출처·레지스트리 승인·도구 설명 오염·러그풀·권한.
artifact = {kind: mcp_server|plugin|skill, name, source, signed, signatureValid, publisher, registryApproved,
            version, tools: [{name, description}], toolsHash, permissions: [...]}  · params.pinnedToolsHash"""
import hashlib
import json
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "supply_review"
KINDS = ("mcp_server", "plugin", "skill")
POISON = re.compile(r"(<\s*important\s*>|ignore (all |any )?(previous|prior) instructions|do not (tell|mention|inform) the user|"
                    r"before (using|calling) this tool.{0,40}(read|send|include)|~/\.ssh|id_rsa|\.env\b|exfiltrat|"
                    r"(이전|기존)\s*지시[를을]?\s*무시|사용자에게\s*(알리지|말하지))", re.I)
BROAD = re.compile(r"^(\*|filesystem:\*|fs:\*|network:\*|shell|exec|all|admin)$", re.I)


def tools_hash(tools: list) -> str:
    return hashlib.sha256(json.dumps([[t.get("name"), t.get("description")] for t in tools], ensure_ascii=False,
                                     sort_keys=True).encode()).hexdigest()


def scan(req: JudgeRequest) -> list[Signal]:
    a = req.artifact or {}
    if a.get("kind") not in KINDS:
        return []
    out: list[Signal] = []

    def sig(rule, score, sev, loc, note):
        out.append(Signal(rule=rule, score=score, severity=sev, evidence=EvidenceItem(kind="supply", location=loc, note=note)))

    if not a.get("signed"):
        sig("unsigned", 0.95, "critical", "artifact.signed", f"{a['kind']} '{a.get('name')}' 서명 없음")
    elif a.get("signatureValid") is False:
        sig("bad-signature", 0.98, "critical", "artifact.signatureValid", "서명 검증 실패")
    if not a.get("registryApproved"):
        sig("unapproved", 0.92, "high", "artifact.registryApproved", "레지스트리 승인 워크플로 미통과")
    for i, t in enumerate(a.get("tools", [])):
        if (m := POISON.search(str(t.get("description", "")))):
            sig("tool-poisoning", 0.96, "critical", f"artifact.tools[{i}].description", f"도구 설명에 숨은 지시('{m.group(0)[:30]}')")
    pinned = req.params.get("pinnedToolsHash") or a.get("pinnedToolsHash")
    if pinned and a.get("tools") and tools_hash(a["tools"]) != pinned:
        sig("rug-pull", 0.94, "critical", "artifact.tools", "승인 이후 도구 정의 변경(러그풀)")
    if str(a.get("version", "")).lower() in ("", "latest", "*", "main", "master"):
        sig("unpinned", 0.7, "medium", "artifact.version", "버전 고정 없음")
    broad = [p for p in a.get("permissions", []) if BROAD.match(str(p))]
    if broad:
        sig("broad-permissions", 0.75, "medium", "artifact.permissions", f"과대 권한 {broad}")
    return out
