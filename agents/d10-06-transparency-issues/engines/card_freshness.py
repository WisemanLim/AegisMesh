"""기본 엔진: 시스템·모델 카드 존재와 최신성 (FR-D10-06). artifact.cards = [{subject, exists, updatedAt, changedAt}]"""
from aegis.engine import artifact_of, signal

id = "card_freshness"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a or "cards" not in a:
        return []
    out = []
    for c in a["cards"]:
        loc = f"card:{c.get('subject')}"
        if not c.get("exists"):
            out.append(signal("missing-card", 0.8, "medium", loc, "시스템·모델 카드 없음"))
        elif c.get("changedAt") and c.get("updatedAt") and c["changedAt"] > c["updatedAt"]:
            out.append(signal("stale-card", 0.75, "low", loc, "변경 이후 카드 미갱신"))
    return out
