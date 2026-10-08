"""기본 엔진: 인덱싱 파이프라인 — 수집 경로 인증·문서 서명·급증 (FR-D8-05).
artifact = {kind: index_update, source, authenticated, documents: [{id, signed, source}], added, baselineDailyAdds}"""
from aegis.engine import artifact_of, signal
from aegis.patterns import find_directive
from aegis.schemas import JudgeRequest

id = "ingestion_audit"


def scan(req: JudgeRequest):
    a = artifact_of(req, "index_update")
    if not a:
        return []
    out = []
    if not a.get("authenticated"):
        out.append(signal("unauthenticated-ingest", 0.95, "critical", "artifact.authenticated", f"인증 없는 수집 경로 {a.get('source')}"))
    docs = a.get("documents", [])
    if docs:
        unsigned = sum(1 for d in docs if not d.get("signed"))
        if unsigned / len(docs) > req.params.get("maxUnsignedRatio", 0.1):
            out.append(signal("unsigned-docs", 0.8, "medium", "artifact.documents", f"서명 없는 문서 {unsigned}/{len(docs)}"))
        bad = [d["id"] for d in docs if find_directive(str(d.get("text", "")))]
        if bad:
            out.append(signal("poisoned-docs", 0.92, "high", "artifact.documents", f"지시문을 담은 위조 의심 문서 {bad[:5]}"))
    base = a.get("baselineDailyAdds")
    if base and a.get("added", 0) > base * req.params.get("spikeFactor", 5):
        out.append(signal("ingest-spike", 0.78, "medium", "artifact.added", f"색인 추가 급증 {a['added']} (기준 {base})"))
    return out
