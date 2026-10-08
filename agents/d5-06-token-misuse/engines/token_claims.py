"""기본 엔진: 토큰 클레임 — 만료·대상·클라이언트·범위·수명 (FR-D5-06).
재현성(NFR-Q4)을 위해 기준 시각은 params.now(epoch 초)로 받는다. 없으면 판정 시각."""
import time

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "token_claims"


def scan(req: JudgeRequest) -> list[Signal]:
    c = (req.auth.token_claims if req.auth else None) or {}
    if not c:
        return []
    p = req.params
    now = p.get("now", time.time())
    out: list[Signal] = []

    def sig(rule, score, sev, note, field):
        out.append(Signal(rule=rule, score=score, severity=sev,
                          evidence=EvidenceItem(kind="token", location=f"auth.tokenClaims.{field}", note=note)))

    if "exp" in c and c["exp"] <= now:
        sig("expired", 0.97, "high", f"만료된 토큰 ({int(now - c['exp'])}초 경과)", "exp")
    if "nbf" in c and c["nbf"] > now + 60:
        sig("not-yet-valid", 0.9, "high", "사용 시작 전 토큰(nbf)", "nbf")
    aud = c.get("aud")
    auds = set(aud if isinstance(aud, list) else [aud] if aud else [])
    if p.get("requireAudience") and not auds:
        sig("audience-missing", 0.9, "high", "수신자(aud) 제한 없는 토큰 — 어디서나 재사용 가능", "aud")
    if p.get("audience") and p["audience"] not in auds:
        sig("audience-mismatch", 0.93, "high", "대상(aud) 불일치 — 다른 서비스용 토큰 재사용", "aud")
    client = c.get("azp") or c.get("client_id")
    if p.get("clientId") and client and client != p["clientId"]:
        sig("client-mismatch", 0.88, "high", "발급 클라이언트와 사용 클라이언트가 다르다", "azp")
    scopes = set(str(c.get("scope", "")).split()) | set(c.get("scp", []) if isinstance(c.get("scp"), list) else [])
    need = set(req.tool.required_scopes) if req.tool else set()
    if need and not need <= scopes:
        sig("scope-insufficient", 0.9, "high", f"토큰 범위에 없는 권한: {', '.join(sorted(need - scopes))}", "scope")
    if "exp" in c and "iat" in c and c["exp"] - c["iat"] > p.get("maxLifetimeSec", 86400):
        sig("long-lived", 0.62, "low", f"토큰 수명 {(c['exp'] - c['iat']) // 3600}시간 > 정책", "exp")
    return out


def explain(req: JudgeRequest) -> dict:
    c = (req.auth.token_claims if req.auth else None) or {}
    p = req.params
    now = p.get("now", time.time())
    aud = c.get("aud")
    life = (c["exp"] - c["iat"]) if isinstance(c.get("exp"), (int, float)) and isinstance(c.get("iat"), (int, float)) else None
    return {"kind": "token", "present": bool(c), "aud": aud if isinstance(aud, list) else [aud] if aud else [], "expected": p.get("audience"),
            "azp": c.get("azp") or c.get("client_id"), "lifetimeSec": life, "maxLifetimeSec": p.get("maxLifetimeSec", 86400),
            "expiresIn": round(c["exp"] - now) if isinstance(c.get("exp"), (int, float)) else None,
            "binding": "dpop" if (c.get("cnf") or {}).get("jkt") else "mtls" if (c.get("cnf") or {}).get("x5t#S256") else "bearer",
            "requireAudience": bool(p.get("requireAudience"))}
