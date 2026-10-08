"""장터 (SCR-C10, FR-D7-01) — 서드파티 에이전트를 신뢰 등급·라이선스·심사 상태로 찾고, 설치는 2인 승인 후 등록 심사(R1~R5).
서드파티는 심사 없이 연결할 수 없다. 이미 설치된 에이전트의 새 버전은 반입 시 심사를 거쳐 무중단 교체(롤링)한다."""
from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import airgap as bundle_fmt
from aegis.ledger_verify import canonical
from app import approvals, ledger, models

TIERS = ("official", "partner", "community", "external")


def _license(manifest: dict) -> str:
    lic = sorted({e.get("license") or "Apache-2.0" for e in manifest["spec"]["engines"]["available"]})
    return ", ".join(lic)


def out(r: models.MarketListing) -> dict:
    m = r.bundle["manifest"]
    return {"id": r.id, "agentId": r.agent_id, "version": r.version, "name": r.name, "nameKo": r.name_ko, "itemId": r.item_id,
            "domain": m["metadata"].get("source", {}).get("domain"), "description": m["metadata"].get("description", ""),
            "publisher": r.publisher, "tier": r.tier, "license": r.license, "isolation": r.isolation, "status": r.status,
            "reviewRef": r.review_id, "source": r.source, "createdAt": r.created_at.isoformat(),
            "gate": m["spec"]["gate"], "verdicts": m["spec"]["verdicts"]}


def list_bundle(s: Session, b: dict, source: str, by: str) -> tuple[models.MarketListing, bool]:
    """번들의 에이전트를 장터에 올린다. 같은 에이전트가 이미 설치(api)돼 있으면 심사 후 롤링 교체."""
    m = b["manifest"]
    aid, ver = m["metadata"]["id"], m["metadata"]["version"]
    pub = s.get(models.PublisherKey, b.get("keyId") or "")
    tier = pub.tier if pub and pub.active else "external"
    lid = f"{aid}@{ver}"[:40]
    row = s.get(models.MarketListing, lid) or models.MarketListing(id=lid, created_at=None)
    row.agent_id, row.version, row.name, row.name_ko = aid, ver, m["metadata"]["name"], m["metadata"]["nameKo"]
    row.item_id, row.publisher, row.tier, row.license = aid.upper(), b.get("keyId"), tier, _license(m)
    row.isolation, row.bundle = m["spec"]["isolation"], b
    row.bundle_sha256, row.source = bundle_fmt.sha256(canonical(b)), source
    if row.created_at is None:
        from app.models import utcnow
        row.created_at, row.status = utcnow(), "available"
    s.merge(row)
    s.flush()
    row = s.get(models.MarketListing, lid)
    installed = s.get(models.Agent, aid)
    rolled = bool(installed and installed.origin == "api" and installed.version != ver)
    if rolled:
        install(s, row, f"{by} (롤링 교체)")
    ledger.append(s, "market", lid, {"event": "listed", "tier": tier, "source": source, "rolling": rolled, "by": by})
    return row, rolled


def request_install(s: Session, row: models.MarketListing, tenant: str, by: str) -> models.Approval:
    if row.status in ("installed", "requested"):
        raise ValueError(f"이미 {row.status}")
    if row.tier == "external":
        raise PermissionError("서명 출처 미확인(external) — 신뢰 게시자 키 등록 후 설치 (MSG-027)")
    apr = approvals.create(s, secrets.token_hex(16), tenant, "market", [], f"장터 설치 {row.id} ({row.name_ko}, {row.tier})", by,
                           action={"type": "market_install", "listing": row.id})
    row.status = "requested"
    ledger.append(s, "market", row.id, {"event": "install_requested", "approval": apr.id, "by": by}, tenant)
    return apr


def install(s: Session, row: models.MarketListing, by: str) -> dict:
    from app import review
    rv, agent = review.submit(s, row.bundle, by)
    row.review_id = rv.id
    row.status = {"active": "installed", "alert_only": "installed", "review_hold": "hold"}.get(rv.outcome, "rejected")
    ledger.append(s, "market", row.id, {"event": "installed" if row.status == "installed" else "install_failed",
                                        "review": rv.id, "outcome": rv.outcome, "by": by})
    return {"applied": "market_install", "listing": row.id, "status": row.status, "review": rv.id, "outcome": rv.outcome}


def apply_action(s: Session, approval: models.Approval) -> dict:
    row = s.get(models.MarketListing, approval.action["listing"])
    return install(s, row, f"approval:{approval.id}")


def listings(s: Session, tier: str | None = None, status: str | None = None) -> list[models.MarketListing]:
    q = select(models.MarketListing).order_by(models.MarketListing.created_at.desc())
    if tier:
        q = q.where(models.MarketListing.tier == tier)
    if status:
        q = q.where(models.MarketListing.status == status)
    return list(s.scalars(q))
