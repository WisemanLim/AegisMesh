"""기본 엔진: 개발자 워크스테이션·러너 상태 (FR-D9-05). artifact = {kind: endpoint_posture, hosts: [{name, edr, integrityOk, plaintextCredentials, hwKey, sessionHours}]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "endpoint_posture"


def scan(req: JudgeRequest):
    a = artifact_of(req, "endpoint_posture")
    if not a:
        return []
    out = []
    for h in a.get("hosts", []):
        loc = f"host:{h.get('name')}"
        if h.get("plaintextCredentials", 0) > 0:
            out.append(signal("plaintext-credentials", 0.94, "critical", loc, f"평문 자격증명 파일 {h['plaintextCredentials']}개"))
        if h.get("integrityOk") is False:
            out.append(signal("integrity-fail", 0.92, "critical", loc, "호스트 무결성 점검 실패"))
        if h.get("edr") is False:
            out.append(signal("no-edr", 0.75, "medium", loc, "호스트 관측(EDR) 꺼짐"))
        if h.get("sessionHours", 0) > req.params.get("maxSessionHours", 12):
            out.append(signal("long-session", 0.7, "low", loc, f"세션 {h['sessionHours']}시간 — 단기 세션 권고"))
        if h.get("hwKey") is False and req.params.get("requireHwKey"):
            out.append(signal("no-hw-key", 0.7, "low", loc, "자격증명 하드웨어 보관 아님"))
    return out
