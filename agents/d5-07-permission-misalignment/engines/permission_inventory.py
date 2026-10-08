"""기본 엔진: 권한 인벤토리 — 부여 대비 사용, 와일드카드, 에이전트 > 소유자 (FR-D5-07).
artifact = {kind: permission_inventory, principals: [{id, type, owner, granted: [...], used: [...]}]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "permission_inventory"


def scan(req: JudgeRequest):
    a = artifact_of(req, "permission_inventory")
    if not a:
        return []
    by_id = {p["id"]: p for p in a.get("principals", [])}
    out = []
    for p in a.get("principals", []):
        loc = f"principal:{p['id']}"
        granted, used = set(p.get("granted", [])), set(p.get("used", []))
        if any(g in ("*", "*:*") or g.endswith(":*") for g in granted):
            out.append(signal("wildcard-grant", 0.9, "high", loc, "와일드카드 권한 부여"))
        unused = sorted(g for g in granted - used if any(k in g for k in ("admin", "write", "delete", "manage")))
        if unused:
            out.append(signal("unused-privileged", 0.75, "medium", loc, f"90일 미사용 고권한 {unused[:5]}"))
        owner = by_id.get(p.get("owner") or "")
        if p.get("type") == "agent" and owner is not None:
            extra = sorted(granted - set(owner.get("granted", [])))
            if extra:
                out.append(signal("agent-exceeds-owner", 0.93, "high", loc, f"에이전트 권한이 소유자({owner['id']})를 넘음 {extra[:5]}"))
    return out
