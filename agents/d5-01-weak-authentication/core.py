"""D5-01 취약 인증 — 미인증·alg=none 은 차단(401), MFA 미적용·워크로드 공유 비밀은 경보."""
from aegis.decide import decide

RULES = {
    "D5-01.no-auth": "auth.method=none (params.requireAuth=false 면 제외), 또는 requireAuth=true 인데 인증 문맥 없음. 차단 → 401.",
    "D5-01.alg-none": "서명 알고리즘 none 토큰. 위조 가능 → 차단.",
    "D5-01.no-mfa": "비밀번호·basic 인증에 MFA 미적용. 경보.",
    "D5-01.shared-secret-agent": "에이전트·서비스가 API 키·비밀번호로 인증. 워크로드 신원(mTLS/SPIFFE) 권장 경보.",
    "D5-01.pass": "인증 강도 검사 통과.",
}


def detect(req, engine):
    return decide("D5-01", engine.scan(req), {"no-auth": "block", "alg-none": "block", "no-mfa": "alert",
                                               "shared-secret-agent": "alert"}, rules=4)
