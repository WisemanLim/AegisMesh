"""기본 엔진: 출력의 자동 렌더 이미지·링크 URL 허용목록 + 쿼리 파라미터 엔트로피 (FR-D1-06)."""
import math
import re
from urllib.parse import parse_qsl, urlparse

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "egress_rules"

MD_IMG = re.compile(r"!\[[^\]]*\]\((?P<u>[^)\s]+)[^)]*\)")
HTML_IMG = re.compile(r"<img[^>]+src\s*=\s*[\"'](?P<u>[^\"']+)[\"']", re.I)
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\((?P<u>https?://[^)\s]+)[^)]*\)")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


ENCODED = re.compile(r"[0-9a-fA-F]{24,}|[A-Za-z0-9+/_-]{24,}={0,2}")


def blob(v: str, bits: float = 3.5) -> bool:
    """인코딩된 데이터 덩어리: 고엔트로피(bits/char 초과)이거나, 긴 hex·base64 형태(hex 는 최대 엔트로피가 4비트라 별도 판정)."""
    return len(v) >= 16 and (entropy(v) > bits or (ENCODED.fullmatch(v) is not None and entropy(v) > bits - 1))


def _allowed(host: str, allow: list[str]) -> bool:
    return any(host == a or host.endswith("." + a) for a in allow)


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    text = req.output or ""
    allow = [a.lower() for a in req.params.get("urlAllowlist", [])]
    bits, render = req.params.get("entropyBits", 3.5), req.params.get("blockAutoRender", True)
    for kind, rx in (("image", MD_IMG), ("image", HTML_IMG), ("link", MD_LINK)):
        for m in rx.finditer(text):
            u = urlparse(m.group("u"))
            if u.scheme not in ("http", "https") or _allowed((u.hostname or "").lower(), allow):
                continue
            ev = dict(kind="span", location="output", offset=m.start(), length=m.end() - m.start())
            noisy = [(k, v) for k, v in parse_qsl(u.query) if blob(v, bits)]
            path_blob = [p for p in u.path.split("/") if len(p) >= 24 and blob(p, bits)]
            if noisy or path_blob:
                out.append(Signal(rule="high-entropy-egress", score=0.93, severity="critical", evidence=EvidenceItem(
                    **ev, note=f"비허용 호스트 {u.hostname} 로 고엔트로피 데이터 전송({kind})")))
            elif kind == "image" and render:
                out.append(Signal(rule="auto-render", score=0.8, severity="medium", evidence=EvidenceItem(
                    **ev, note=f"비허용 호스트 {u.hostname} 이미지 자동 렌더")))
    return out


def explain(req: JudgeRequest) -> dict:
    """출력의 이미지·링크 URL 별 허용 여부·최대 엔트로피·조치 (SCR-E04)."""
    text = req.output or ""
    allow = [a.lower() for a in req.params.get("urlAllowlist", [])]
    bits, render = req.params.get("entropyBits", 3.5), req.params.get("blockAutoRender", True)
    urls = []
    for kind, rx in (("image", MD_IMG), ("image", HTML_IMG), ("link", MD_LINK)):
        for m in rx.finditer(text):
            u = urlparse(m.group("u"))
            host = (u.hostname or "").lower()
            vals = [v for _, v in parse_qsl(u.query)] + [p for p in u.path.split("/") if len(p) >= 24]
            ok = u.scheme not in ("http", "https") or _allowed(host, allow)
            hot = [v for v in vals if blob(v, bits)]
            urls.append({"kind": kind, "host": host, "allowed": ok, "maxEntropy": round(max((entropy(v) for v in vals), default=0.0), 2),
                         "encodedParams": len(hot),
                         "action": "pass" if ok else "block" if hot else "transform" if kind == "image" and render else "pass"})
    return {"kind": "egress", "urls": urls, "entropyBits": bits, "blockAutoRender": render, "allowlist": allow}
