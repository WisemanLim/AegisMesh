"""기본 엔진: 주체별 토큰·시간·동시성·저장소 쿼터 (FR-D6-06, LLM06). params.usage / params.quota (호출자 집계)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "quota_check"
DIMS = ("tokens", "seconds", "concurrency", "storageMb", "costUsd")


def scan(req: JudgeRequest) -> list[Signal]:
    use, quota = req.params.get("usage") or {}, req.params.get("quota") or {}
    out: list[Signal] = []
    for d in DIMS:
        if d in use and d in quota and quota[d]:
            r = use[d] / quota[d]
            if r >= 1:
                out.append(Signal(rule="quota-exceeded", score=0.95, severity="high", evidence=EvidenceItem(
                    kind="usage", location=f"params.usage.{d}", note=f"{d} {use[d]}/{quota[d]} 쿼터 초과")))
            elif r >= req.params.get("warnRatio", 0.9):
                out.append(Signal(rule="quota-near", score=0.7, severity="low", evidence=EvidenceItem(
                    kind="usage", location=f"params.usage.{d}", note=f"{d} {r:.0%} 사용 — 백프레셔 권고")))
    if req.tool and isinstance(req.tool.args.get("max_tokens"), int) and req.tool.args["max_tokens"] > req.params.get("maxTokensPerCall", 32000):
        out.append(Signal(rule="oversized-call", score=0.8, severity="medium", evidence=EvidenceItem(
            kind="usage", location="args.max_tokens", note="호출당 토큰 상한 초과 요청")))
    return out


def explain(req: JudgeRequest) -> dict:
    use, quota = req.params.get("usage") or {}, req.params.get("quota") or {}
    return {"kind": "quota", "dims": [{"dim": d, "used": use.get(d), "quota": quota.get(d),
                                        "ratio": round(use[d] / quota[d], 3) if d in use and quota.get(d) else None} for d in DIMS if d in use or d in quota],
            "warnRatio": req.params.get("warnRatio", 0.9), "note": "초과 = 차단(새 실행 거부), 근접 = 백프레셔 권고(429·대기열·강등 실행은 호출자)"}
