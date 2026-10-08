"""기본 엔진: 패키지 휴리스틱 (FR-D7-03) — 설치 스크립트 원격 실행, 난독화, 타이포스쿼팅, 신규·저신뢰 패키지.
artifact = {kind: package, name, ecosystem, installScripts: {..}, files: [{path, content}], publishedDaysAgo, downloads}"""
import re

from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "package_heuristics"
REMOTE_EXEC = re.compile(r"(curl|wget|Invoke-WebRequest|iwr)\b[^\n]*(\|\s*(ba)?sh|\|\s*python|-o\s*/tmp)|node\s+-e|python\d?\s+-c|base64\s+(-d|--decode)", re.I)
OBFUSC = re.compile(r"(eval\s*\(\s*(atob|Buffer\.from|base64|unescape)|exec\s*\(\s*(base64|codecs|zlib)\.|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}|"
                    r"fromCharCode\((\d+,\s*){20,}|[A-Za-z0-9+/]{200,}={0,2})", re.I)
POPULAR = ["requests", "numpy", "pandas", "urllib3", "django", "flask", "lodash", "react", "express", "axios", "openai",
           "anthropic", "langchain", "torch", "tensorflow", "boto3", "colorama", "setuptools", "crypto-js", "jsonwebtoken"]


def lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def scan(req: JudgeRequest):
    a = artifact_of(req, "package")
    if not a:
        return []
    out = []
    for hook, cmd in (a.get("installScripts") or {}).items():
        if REMOTE_EXEC.search(str(cmd)):
            out.append(signal("install-remote-exec", 0.96, "critical", f"artifact.installScripts.{hook}", "설치 스크립트가 원격 코드를 내려받아 실행"))
    for f in a.get("files", []):
        if OBFUSC.search(str(f.get("content", ""))):
            out.append(signal("obfuscation", 0.9, "high", f"file:{f.get('path')}", "난독화된 실행 코드(eval·base64·hex 덩어리)"))
            break
    name = str(a.get("name", "")).lower()
    popular = req.params.get("popularPackages", POPULAR)
    near = [p for p in popular if p != name and lev(name.replace("_", "-"), p) <= (1 if len(p) <= 6 else 2)]
    if near:
        out.append(signal("typosquat", 0.85, "high", "artifact.name", f"인기 패키지 {near[0]} 와 유사한 이름"))
    if a.get("publishedDaysAgo", 999) < 30 and a.get("downloads", 10**9) < 1000:
        out.append(signal("low-trust", 0.7, "medium", "artifact.publishedDaysAgo", "게시 30일 미만·다운로드 1천 미만 — 격리 사용 권고"))
    return out
