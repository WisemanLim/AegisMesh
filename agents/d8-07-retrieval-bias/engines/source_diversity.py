"""기본 엔진: 검색 결과 출처 분포 (FR-D8-07) — 한 출처의 과대 대표."""
from collections import Counter

from aegis.engine import signal
from aegis.schemas import JudgeRequest

id = "source_diversity"


def scan(req: JudgeRequest):
    n = len(req.retrieval)
    if n < req.params.get("minDocs", 5):
        return []
    src, cnt = Counter(d.source for d in req.retrieval).most_common(1)[0]
    share = cnt / n
    if share > req.params.get("maxSourceShare", 0.6):
        return [signal("source-dominance", 0.75, "low", "retrieval", f"출처 '{src}' 가 {share:.0%} ({cnt}/{n}) — 다양성 부족", "retrieval")]
    return []
