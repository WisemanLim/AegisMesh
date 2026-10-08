"""aegismesh — 시드 (make db-seed). 도식 80 항목 · 내장 에이전트 · 프로파일 · 기본 정책. 여러 번 실행해도 안전(멱등)."""
from app import db, registry


def run() -> dict:
    with db.system_session() as s, s.begin():
        from app import ledger
        for chain in (ledger.PLATFORM, "default"):
            ledger.ensure_chain(s, chain)
        items = registry.sync_risk_items(s)
        s.flush()
        agents = registry.sync_builtin_agents(s)
        extra = {}
        try:
            from app import policy, profiles
            extra["profiles"] = profiles.sync(s)
            extra["policy"] = policy.ensure_default(s)
        except ImportError:  # Epic 3 이전
            pass
    return {"riskItems": items, "agents": len(agents), **extra}


if __name__ == "__main__":
    print("seed:", run())
