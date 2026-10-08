"""기본 엔진: 암호화 인벤토리 — 내부 구간 평문·mTLS·인증서 만료·TLS 판본·저장 암호화 (FR-D9-03).
artifact = {kind: crypto_inventory, endpoints: [{name, tls, mtls, tlsVersion, certExpiresInDays}], stores: [{name, encrypted}]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "crypto_inventory"


def scan(req: JudgeRequest):
    a = artifact_of(req, "crypto_inventory")
    if not a:
        return []
    out = []
    for e in a.get("endpoints", []):
        loc = f"endpoint:{e.get('name')}"
        if e.get("tls") is False:
            out.append(signal("plaintext", 0.95, "critical", loc, "평문 통신 구간"))
        elif e.get("mtls") is False and req.params.get("requireMtls", True):
            out.append(signal("no-mtls", 0.75, "medium", loc, "내부 구간 상호 TLS 아님(NFR-D3)"))
        d = e.get("certExpiresInDays")
        if d is not None and d <= 0:
            out.append(signal("cert-expired", 0.95, "critical", loc, "인증서 만료"))
        elif d is not None and d < req.params.get("certWarnDays", 14):
            out.append(signal("cert-expiring", 0.75, "medium", loc, f"인증서 {d}일 후 만료"))
        if str(e.get("tlsVersion", "1.2")) in ("1.0", "1.1", "SSLv3"):
            out.append(signal("weak-tls", 0.8, "medium", loc, f"TLS {e['tlsVersion']}"))
    for s in a.get("stores", []):
        if s.get("encrypted") is False:
            out.append(signal("unencrypted-store", 0.92, "high", f"store:{s.get('name')}", "저장 데이터 미암호화(NFR-D2)"))
    return out
