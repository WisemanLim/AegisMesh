"""기본 엔진: 세션 결속 — 장치 지문·IP 가 세션 발급 시점과 일치하는지, 위치 이동이 물리적으로 가능한지 (FR-D5-03 · MSG-030)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "session_binding"


def scan(req: JudgeRequest) -> list[Signal]:
    s = req.session
    if s is None:
        return []
    if s.bound_key and s.proof_key != s.bound_key:                   # FR-D5-03 — 바인딩 토큰을 증명 없이/다른 키로
        return [Signal(rule="token-replay", score=0.97, severity="critical", evidence=EvidenceItem(
            kind="session", location="session.proofKey",
            note="소유 증명 없이 바인딩 토큰 사용" if not s.proof_key else "다른 키의 소유 증명 — 토큰 탈취 의심"))]
    fp_changed = bool(s.bound_fingerprint and s.fingerprint and s.bound_fingerprint != s.fingerprint)
    ip_changed = bool(s.bound_ip and s.ip and s.bound_ip != s.ip)
    out = []
    if fp_changed:
        out.append(Signal(rule="fingerprint-mismatch", score=0.93 if ip_changed else 0.88, severity="critical", evidence=EvidenceItem(
            kind="session", location="session.fingerprint",
            note="세션 장치 지문 불일치" + (" + IP 변경" if ip_changed else ""))))
    if s.travel_kmh:                                                  # 호출자(지오 IP)가 임계를 넘은 이동만 넘긴다
        out.append(Signal(rule="impossible-travel", score=0.9, severity="high", evidence=EvidenceItem(
            kind="session", location="session.travelKmh", note=f"불가능한 이동 {s.travel_km or 0:,.0f} km · {s.travel_kmh:,.0f} km/h")))
    if out:
        return out
    if ip_changed:
        return [Signal(rule="ip-change", score=0.65, severity="low", evidence=EvidenceItem(
            kind="session", location="session.ip", note="같은 장치에서 IP 변경(모바일 망 전환 가능)"))]
    return []


def explain(req: JudgeRequest) -> dict:
    s = req.session
    if s is None:
        return {"kind": "session", "session": None}
    return {"kind": "session", "session": s.id, "bound": bool(s.bound_fingerprint or s.bound_ip or s.bound_key),
            "keyBound": bool(s.bound_key), "proofMatches": (s.proof_key == s.bound_key) if s.bound_key else None,
            "fingerprintChanged": bool(s.bound_fingerprint and s.fingerprint and s.bound_fingerprint != s.fingerprint),
            "ipChanged": bool(s.bound_ip and s.ip and s.bound_ip != s.ip), "travelKmh": s.travel_kmh,
            "advice": "소유 증명(DPoP·mTLS) 바인딩 + 짧은 수명. 새 장치·위치 = 재인증, 지문 불일치 = 차단, 불가능한 이동 = 재인증·경보"}
