"""기본 엔진: 파일 도구 경로 규칙 — 경로 이탈·허용 루트 밖 쓰기·민감 파일·대량 삭제 (FR-D3-04)."""
import posixpath
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "path_rules"

FILE_TOOL = re.compile(r"(file|fs|path|dir|folder|write|read|delete|remove|move|rename|copy|edit|upload|download|unlink|mkdir)", re.I)
WRITE_TOOL = re.compile(r"(write|delete|remove|move|rename|edit|append|create|unlink|chmod|put|save|overwrite)", re.I)
PATH_KEY = re.compile(r"(path|file|filename|dir|directory|dest|destination|src|source|target|glob|pattern)$", re.I)
SENSITIVE = re.compile(r"(^|/)(\.env(?!\.(example|sample|template|dist)$)(\.[\w-]+)?|id_(rsa|ed25519|ecdsa)(\.pub)?|\.git/(config|credentials)|\.aws/credentials|"
                       r"\.npmrc|\.pypirc|\.netrc|[\w-]*\.(pem|key|p12|pfx|kdbx)|secrets?\.(ya?ml|json))$", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    t = req.tool
    if t is None or not FILE_TOOL.search(t.name):
        return []
    roots = [r.rstrip("/") or "/" for r in req.params.get("allowedPaths", ["/workspace"])]
    ro = [r.rstrip("/") or "/" for r in req.params.get("readOnlyPaths", [])]
    writing = bool(WRITE_TOOL.search(t.name))
    out: list[Signal] = []
    for k, v in t.args.items():
        if not isinstance(v, str) or not PATH_KEY.search(k):
            continue
        loc = f"args.{k}"
        if ".." in v.replace("\\", "/").split("/"):
            out.append(Signal(rule="path-traversal", score=0.93, severity="high",
                              evidence=EvidenceItem(kind="path", location=loc, note="상위 디렉터리 이탈(..)")))
            continue
        norm = posixpath.normpath(v if v.startswith("/") else posixpath.join(roots[0], v))
        if SENSITIVE.search(norm):
            out.append(Signal(rule="sensitive-file", score=0.9, severity="high",
                              evidence=EvidenceItem(kind="path", location=loc, note=f"민감 파일 유형 {posixpath.basename(norm)}")))
        if not any(norm == r or norm.startswith(r + "/") for r in roots):
            out.append(Signal(rule="outside-root", score=0.88 if writing else 0.7, severity="high" if writing else "medium",
                              evidence=EvidenceItem(kind="path", location=loc, note=f"허용 루트 {roots} 밖 {'쓰기' if writing else '읽기'}")))
        if writing and any(norm == r or norm.startswith(r + "/") for r in ro):
            out.append(Signal(rule="read-only-path", score=0.9, severity="high",
                              evidence=EvidenceItem(kind="path", location=loc, note=f"읽기 전용 마운트 경로에 쓰기 ({norm})")))
        if writing and re.search(r"(^|/)\*\*?$|\*\.\*$", v):
            out.append(Signal(rule="mass-change", score=0.82, severity="high",
                              evidence=EvidenceItem(kind="path", location=loc, note="와일드카드 대량 변경")))
    return out


def explain(req: JudgeRequest) -> dict:
    """경로 정규화 시험 — 입력 경로 → 정규화 결과·허용 루트·읽기 전용·민감 파일·조치 (SCR-G03)."""
    t = req.tool
    roots = [r.rstrip("/") or "/" for r in req.params.get("allowedPaths", ["/workspace"])]
    ro = [r.rstrip("/") or "/" for r in req.params.get("readOnlyPaths", [])]
    rows = []
    if t is not None:
        writing = bool(WRITE_TOOL.search(t.name))
        for k, v in t.args.items():
            if not isinstance(v, str) or not PATH_KEY.search(k):
                continue
            trav = ".." in v.replace("\\", "/").split("/")
            norm = posixpath.normpath(v if v.startswith("/") else posixpath.join(roots[0], v))
            inside = any(norm == r or norm.startswith(r + "/") for r in roots)
            rdonly = any(norm == r or norm.startswith(r + "/") for r in ro)
            action = ("block" if trav or SENSITIVE.search(norm) or (writing and (rdonly or not inside))
                      else "require_approval" if not inside else "allow")
            rows.append({"arg": f"args.{k}", "input": v[:200], "normalized": norm, "traversal": trav, "insideRoot": inside,
                         "readOnly": rdonly, "sensitive": bool(SENSITIVE.search(norm)), "write": writing, "action": action})
    return {"kind": "paths", "roots": roots, "readOnly": ro, "paths": rows}
