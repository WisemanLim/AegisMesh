"""기본 엔진: 상위 API 공급자 — 이그레스 허용목록·인증서 고정·응답 무결성·공급망 증명 (FR-D7-07).
artifact = {kind: api_provider, name, host, presentedFingerprint, pinnedFingerprint, responseSignatureValid, attestation}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "provider_integrity"


def scan(req: JudgeRequest):
    a = artifact_of(req, "api_provider")
    if not a:
        return []
    out = []
    allow = req.params.get("egressAllowlist")
    host = str(a.get("host", "")).lower()
    if allow is not None and not any(host == h or host.endswith("." + h) for h in allow):
        out.append(signal("egress-denied", 0.95, "critical", "artifact.host", f"이그레스 허용목록 밖 공급자 {host}"))
    if a.get("pinnedFingerprint") and a.get("presentedFingerprint") != a["pinnedFingerprint"]:
        out.append(signal("pin-mismatch", 0.97, "critical", "artifact.presentedFingerprint", "인증서 지문 불일치(중간 경로 침해 의심)"))
    if a.get("responseSignatureValid") is False:
        out.append(signal("response-tampered", 0.96, "critical", "artifact.responseSignatureValid", "응답 서명 검증 실패(조작)"))
    if a.get("attestation") is False:
        out.append(signal("no-attestation", 0.7, "medium", "artifact.attestation", "공급망 증명 없음"))
    return out
