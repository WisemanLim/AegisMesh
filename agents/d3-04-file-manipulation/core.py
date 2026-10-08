"""D3-04 파일 조작 — 경로 이탈·민감 파일·루트 밖 쓰기는 차단, 대량 변경·루트 밖 읽기는 승인."""
from aegis.decide import decide

RULES = {
    "D3-04.path-traversal": "경로에 '..' — 허용 루트 이탈. 차단.",
    "D3-04.sensitive-file": "자격증명·키·.env 등 민감 파일 접근. 차단.",
    "D3-04.outside-root": "허용 루트(params.allowedPaths, 기본 /workspace) 밖. 쓰기는 차단, 읽기는 승인.",
    "D3-04.mass-change": "와일드카드 대량 변경. 사람 승인.",
    "D3-04.read-only-path": "읽기 전용 마운트 경로에 쓰기. 차단.",
         "D3-04.pass": "파일 경로 규칙 통과.",
}


def detect(req, engine):
    signals = engine.scan(req)
    write_outside = any(s.rule == "outside-root" and s.severity == "high" for s in signals)
    return decide("D3-04", signals, {"path-traversal": "block", "sensitive-file": "block", "mass-change": "require_approval", "read-only-path": "block",
                                     "outside-root": "block" if write_outside else "require_approval"}, rules=5)
