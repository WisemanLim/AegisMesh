"""기본 엔진: 이그레스 기본 차단·흐름 암호화·상호 인증 (FR-D9-06). artifact = {kind: network_policy, egressDefault, mtls, flows: [{src, dst, port, tls, external}]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "network_policy"


def scan(req: JudgeRequest):
    a = artifact_of(req, "network_policy")
    if not a:
        return []
    out = []
    if a.get("egressDefault", "deny") != "deny":
        out.append(signal("egress-open", 0.8, "medium", "artifact.egressDefault", "이그레스 기본 허용"))
    if a.get("mtls") is False:
        out.append(signal("no-mutual-auth", 0.78, "medium", "artifact.mtls", "서비스 간 상호 인증 없음"))
    for i, f in enumerate(a.get("flows", [])):
        if f.get("external") and f.get("tls") is False:
            out.append(signal("plaintext-external", 0.95, "critical", f"artifact.flows[{i}]", f"외부 평문 흐름 {f.get('src')}→{f.get('dst')}:{f.get('port')}"))
        elif not f.get("external") and f.get("tls") is False and f.get("mtls") is False:   # 메시 mTLS 밖(사이드카 없음)의 평문 내부 흐름
            out.append(signal("plaintext-internal", 0.9, "high", f"artifact.flows[{i}]", f"상호 TLS 밖 평문 내부 흐름 {f.get('src')}→{f.get('dst')}:{f.get('port')}"))
        if f.get("unexpectedRoute"):
            out.append(signal("route-anomaly", 0.9, "high", f"artifact.flows[{i}]", "예상 밖 경로(가로채기 의심)"))
    return out
