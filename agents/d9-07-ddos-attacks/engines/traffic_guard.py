"""기본 엔진: 트래픽 남용 (FR-D9-07). artifact = {kind: traffic_stats, rps, baselineRps, topClient, topClientShare, rateLimit, queueDepth, autoscaleMax}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "traffic_guard"


def scan(req: JudgeRequest):
    a = artifact_of(req, "traffic_stats")
    if not a:
        return []
    out = []
    if not a.get("rateLimit"):
        out.append(signal("no-rate-limit", 0.8, "medium", "artifact.rateLimit", "엣지 레이트리밋 없음"))
    if a.get("autoscaleMax") in (None, 0, "unbounded"):
        out.append(signal("unbounded-scale", 0.72, "medium", "artifact.autoscaleMax", "자동 확장 상한 없음(비용 폭주)"))
    base = a.get("baselineRps") or 0
    if base and a.get("rps", 0) > base * req.params.get("surgeFactor", 5):
        concentrated = a.get("topClientShare", 0) > req.params.get("maxClientShare", 0.5)
        out.append(signal("flood" if concentrated else "surge", 0.94 if concentrated else 0.75, "critical" if concentrated else "medium",
                          "artifact.rps", f"요청 {a['rps']}rps (기준 {base})" + (f", 상위 클라이언트 {a.get('topClient')} {a['topClientShare']:.0%}" if concentrated else "")))
    return out
