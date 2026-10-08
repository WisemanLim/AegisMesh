"""기본 엔진: 감사 추적 — 원장 무결성·체크포인트 간격·익명 행동 (FR-D10-04)."""
from aegis.engine import artifact_of, signal

id = "audit_trail"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a or "ledger" not in a:
        return []
    led = a["ledger"]
    out = []
    if led.get("ok") is False:
        out.append(signal("ledger-broken", 0.99, "critical", "artifact.ledger", f"증적 원장 무결성 실패: {led.get('detail')}"))
    if led.get("sinceCheckpoint", 0) > req.params.get("maxUncheckpointed", 1000):
        out.append(signal("stale-checkpoint", 0.75, "medium", "artifact.ledger", f"서명 체크포인트 이후 {led['sinceCheckpoint']}건 미서명"))
    anon = (a.get("approvals") or {}).get("anonymousActions", 0)
    if anon:
        out.append(signal("anonymous-actions", 0.8, "medium", "artifact.approvals", f"주체 없는 행동 기록 {anon}건 — 누가 했는지 재구성 불가"))
    return out
