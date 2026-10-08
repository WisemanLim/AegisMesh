"""기본 엔진: 검색 문서·도구 응답의 출처 신뢰 등급 + 삽입 콘텐츠 인젝션 스캔 (FR-D8-01). STEP3 컨텍스트 조립 재검사."""
from aegis.engine import signal
from aegis.patterns import find_directive
from aegis.schemas import JudgeRequest

id = "context_scan"


def scan(req: JudgeRequest):
    out = []
    trusted = set(req.params.get("trustedSources", []))
    for d in req.retrieval:
        if (m := find_directive(d.text)):
            hi = d.trust == "untrusted" and d.source not in trusted
            out.append(signal("poisoned-doc", 0.93 if hi else 0.7, "high" if hi else "medium", f"retrieval:{d.id}",
                              f"{d.source} 문서에 모델 대상 지시 — 오염 문서 제외", "retrieval", m.start(), m.end() - m.start()))
        elif req.params.get("requireSignedDocs") and d.signed is False:
            out.append(signal("unsigned-doc", 0.72, "medium", f"retrieval:{d.id}", "서명 없는 문서가 컨텍스트에 포함", "retrieval"))
    return out
