"""기본 엔진: 인증 강도 — 미인증·alg=none·MFA 없는 비밀번호·에이전트의 공유 비밀 인증 (FR-D5-01)."""
from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "auth_strength"


def scan(req: JudgeRequest) -> list[Signal]:
    a = req.auth
    if a is None:  # 호출자가 인증 문맥을 넘기지 않음 ≠ 미인증 — requireAuth=true 일 때만 판정
        if req.params.get("requireAuth"):
            return [Signal(rule="no-auth", score=0.95, severity="critical",
                           evidence=EvidenceItem(kind="auth", location="auth", note="인증 정보 없음"))]
        return []
    out: list[Signal] = []
    if a.method == "none" and req.params.get("requireAuth", True):
        out.append(Signal(rule="no-auth", score=0.95, severity="critical",
                          evidence=EvidenceItem(kind="auth", location="auth.method", note="method=none")))
    claims = a.token_claims or {}
    if str(claims.get("alg", "")).lower() == "none":
        out.append(Signal(rule="alg-none", score=0.97, severity="critical",
                          evidence=EvidenceItem(kind="auth", location="auth.tokenClaims.alg", note="서명 없는 토큰(alg=none)")))
    if a.method in ("password", "basic") and not a.mfa:
        out.append(Signal(rule="no-mfa", score=0.7, severity="medium",
                          evidence=EvidenceItem(kind="auth", location="auth.mfa", note=f"{a.method} 인증에 MFA 없음")))
    p = req.subject.principal
    if p is not None and p.type in ("agent", "service") and a.method in ("api_key", "password", "basic"):
        out.append(Signal(rule="shared-secret-agent", score=0.72, severity="medium",
                          evidence=EvidenceItem(kind="auth", location="auth.method",
                                                note=f"워크로드({p.type})가 {a.method} 로 인증 — mTLS·SPIFFE 권장")))
    return out


def explain(req: JudgeRequest) -> dict:
    a, p = req.auth, req.subject.principal
    return {"kind": "authn", "method": a.method if a else None, "mfa": a.mfa if a else None, "signed": a.signed_identity if a else None,
            "attested": bool(a and a.attested_spiffe_id), "principalType": p.type if p else None,
            "alg": ((a.token_claims or {}).get("alg") if a else None), "requireAuth": req.params.get("requireAuth", True),
            "advice": "워크로드는 SPIFFE SVID(mTLS) 또는 OIDC 로 — 정적 API 키·공유 비밀은 전환 후 폐기"}
