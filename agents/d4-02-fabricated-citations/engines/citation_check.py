"""기본 엔진: 인용 식별자 실재 확인 — URL·DOI·arXiv 가 제공 근거·허용 목록에 있는지, DOI·arXiv 형식이 유효한지 (FR-D4-02).
네트워크 조회는 하지 않는다(재현성·폐쇄망). 실재 목록은 params.knownCitations 로 받는다."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "citation_check"
URL = re.compile(r"https?://[^\s)\]>\"']+")
DOI = re.compile(r"(?:doi:\s*|https?://doi\.org/)(10\.[^\s\"<>]+)|\b(10\.\d{4,9}/[^\s\"<>]+)", re.I)
ARXIV = re.compile(r"\barXiv:\s*(\d{4})\.(\d{4,5})(v\d+)?", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    text = req.output or ""
    known = {c.rstrip("/.").lower() for c in req.params.get("knownCitations", [])}
    known |= {d.url.rstrip("/.").lower() for d in req.retrieval if d.url}
    out: list[Signal] = []

    def flag(m, rule, score, note):
        out.append(Signal(rule=rule, score=score, severity="medium", evidence=EvidenceItem(
            kind="span", location="output", offset=m.start(), length=m.end() - m.start(), note=note)))

    for m in ARXIV.finditer(text):
        yy, mm = int(m.group(1)[:2]), int(m.group(1)[2:])
        if not (1 <= mm <= 12 and 7 <= yy <= 99):
            flag(m, "invalid-id", 0.9, "형식상 존재할 수 없는 arXiv 식별자")
        elif f"arxiv:{m.group(1)}.{m.group(2)}" not in {re.sub(r"v\d+$", "", k.replace(" ", "")) for k in known}:
            flag(m, "unverified", 0.75, "근거·허용 목록에 없는 arXiv 인용")
    for m in DOI.finditer(text):
        doi = (m.group(1) or m.group(2)).rstrip(".,;")
        if not re.fullmatch(r"10\.\d{4,9}/[-._;()/:A-Za-z0-9]+", doi):
            flag(m, "invalid-id", 0.9, "형식이 잘못된 DOI")
        elif doi.lower() not in known and f"https://doi.org/{doi}".lower() not in known:
            flag(m, "unverified", 0.75, "근거·허용 목록에 없는 DOI")
    for m in URL.finditer(text):
        u = m.group(0).rstrip("/.,;").lower()
        if "doi.org/" in u:
            continue
        if known and u not in known and not req.params.get("allowUnlistedUrls", False):
            flag(m, "unverified", 0.72, "근거 문서에 없는 URL 인용")
    return out


def explain(req: JudgeRequest) -> dict:
    """인용 식별자별 형식·실재(근거·허용 목록)·조치 (SCR-H02)."""
    text = req.output or ""
    known = {c.rstrip("/.").lower() for c in req.params.get("knownCitations", [])} | {d.url.rstrip("/.").lower() for d in req.retrieval if d.url}
    flagged = {(s.evidence.offset, s.rule) for s in scan(req)}
    rows = []
    for kind, rx in (("arxiv", ARXIV), ("doi", DOI), ("url", URL)):
        for m in rx.finditer(text):
            ref = m.group(0).rstrip("/.,;")
            if kind == "url" and "doi.org/" in ref.lower():
                continue
            rule = next((r for o, r in flagged if o == m.start()), None)
            rows.append({"kind": kind, "ref": ref[:120], "known": ref.lower() in known, "rule": rule,
                         "action": "remove" if rule else "keep"})
    return {"kind": "citations", "citations": rows, "knownCount": len(known),
            "note": "네트워크 조회 없이 근거 문서 URL·허용 목록(knownCitations)으로 실재 확인 — 미검증 인용은 [인용 미검증] 으로 치환"}
