"""폐쇄망 운영 (FR-P14, NFR-C3, SCR-A05·R05) — 내부 신뢰 저장소 + 서명 번들 반입(검증 → 적용).

반입 단계: ① 서명(신뢰 저장소 키) ② 구성요소·SBOM 해시 ③ SBOM 취약점 기준(critical 0·high ≤3) ④ 적용.
한 단계라도 실패하면 아무것도 적용하지 않는다. 적용: 프로파일 갱신 · 내부 취약점 DB 갱신 ·
설치된 서드파티 에이전트 새 버전은 등록 심사 후 무중단 교체(롤링) · 새 에이전트는 장터 목록.
"""
from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import airgap as bundle_fmt
from app import approvals, ledger, models
from app.core.config import settings

SEED_VULNDB = Path(__file__).resolve().parent.parent / "airgap" / "vulndb.json"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _vulndb_path() -> Path:
    return Path(settings.registry_dir).parent / "vulndb.json"


def vulndb() -> dict:
    p = _vulndb_path()
    return json.loads((p if p.exists() else SEED_VULNDB).read_text(encoding="utf-8"))


# ── 신뢰 저장소 ───────────────────────────────────────────────
def trust(s: Session) -> dict[str, str]:
    now = utcnow()
    return {k.key_id: k.public_key for k in s.scalars(select(models.TrustKey).where(models.TrustKey.status == "active"))
            if not k.expires_at or (k.expires_at if k.expires_at.tzinfo else k.expires_at.replace(tzinfo=timezone.utc)) > now}


def key_out(k: models.TrustKey) -> dict:
    return {"keyId": k.key_id, "name": k.name, "publicKey": k.public_key, "purpose": k.purpose, "status": k.status,
            "addedBy": k.added_by, "approvalRef": k.approval_id, "createdAt": k.created_at.isoformat(),
            "expiresAt": k.expires_at.isoformat() if k.expires_at else None}


def request_key(s: Session, key_id: str, name: str, public_key: str, by: str) -> models.TrustKey:
    """신뢰 키 추가는 2인 승인 후 활성 (SCR-R05 #6)."""
    if len(base64.b64decode(public_key, validate=True)) != 32:
        raise ValueError("publicKey 는 base64 Ed25519 공개키(32바이트)")
    if s.get(models.TrustKey, key_id):
        raise KeyError(key_id)
    k = models.TrustKey(key_id=key_id, name=name, public_key=public_key, purpose="bundle", status="pending", added_by=by,
                        created_at=utcnow())
    s.add(k)
    s.flush()
    apr = approvals.create(s, secrets.token_hex(16), "default", "trust", [], f"신뢰 저장소 키 추가 {key_id} ({name})", by,
                           action={"type": "trust_key_add", "keyId": key_id})
    k.approval_id = apr.id
    ledger.append(s, "trust", key_id, {"event": "key_requested", "name": name, "by": by, "approval": apr.id})
    return k


def request_revoke(s: Session, key_id: str, by: str, reason: str) -> models.Approval:
    k = s.get(models.TrustKey, key_id)
    if k is None or k.status != "active":
        raise KeyError(key_id)
    return approvals.create(s, secrets.token_hex(16), "default", "trust", [], f"신뢰 저장소 키 폐기 {key_id}: {reason}", by,
                            action={"type": "trust_key_revoke", "keyId": key_id})


def apply_action(s: Session, approval: models.Approval) -> dict:
    act = approval.action
    k = s.get(models.TrustKey, act["keyId"])
    if act["type"] == "trust_key_add":
        k.status = "active"
    else:
        k.status, k.revoked_at = "revoked", utcnow()
    ledger.append(s, "trust", k.key_id, {"event": "key_" + k.status, "approval": approval.id})
    return {"applied": act["type"], "keyId": k.key_id, "status": k.status}


# ── 반입 ─────────────────────────────────────────────────────
def import_bundle(s: Session, data: bytes, by: str) -> models.BundleImport:
    imp = models.BundleImport(id=f"imp_{secrets.token_hex(6)}", sha256=bundle_fmt.sha256(data), status="rejected", steps=[],
                              applied={}, imported_by=by, created_at=utcnow())
    try:
        v = bundle_fmt.verify(data, trust(s), vulndb())
    except bundle_fmt.BundleError as exc:
        imp.steps = exc.passed + [{"step": exc.step, "ok": False, "detail": exc.msg}]
        try:
            imp.version = bundle_fmt.read(data)[0].get("version")
            imp.key_id = bundle_fmt.read(data)[0].get("keyId")
        except bundle_fmt.BundleError:
            pass
        s.add(imp)
        s.flush()
        ledger.append(s, "airgap", imp.id, {"event": "bundle_rejected", "step": exc.step, "detail": exc.msg, "sha256": imp.sha256, "by": by})
        return imp
    m = v["manifest"]
    imp.version, imp.key_id, imp.steps = m["version"], m["keyId"], v["steps"]
    applied: dict = {"profiles": [], "vulndb": None, "rolling": [], "listed": []}
    for c in m["components"]:
        data_ = v["files"][c["path"]]
        if c["kind"] == "profile":
            doc = yaml.safe_load(data_)
            from app.profiles import ProfileDoc
            ProfileDoc.model_validate(doc)
            s.merge(models.Profile(id=doc["metadata"]["id"], name_ko=doc["metadata"]["nameKo"], spec=doc, tenant=None,
                                   created_by=f"bundle:{m['version']}"))
            applied["profiles"].append(doc["metadata"]["id"])
        elif c["kind"] == "vulndb":
            p = _vulndb_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data_)
            applied["vulndb"] = json.loads(data_).get("version")
    for c in m["components"]:
        if c["kind"] != "agent-bundle":
            continue
        from app import market
        listing, rolled = market.list_bundle(s, json.loads(v["files"][c["path"]]), f"bundle:{imp.id}", by)
        (applied["rolling"] if rolled else applied["listed"]).append({"listing": listing.id, "status": listing.status})
    imp.status, imp.applied = "imported", applied
    imp.steps = v["steps"] + [{"step": "apply", "ok": True,
                               "detail": f"프로파일 {len(applied['profiles'])} · 취약점 DB {applied['vulndb'] or '변경 없음'} · "
                                         f"롤링 교체 {len(applied['rolling'])} · 장터 등록 {len(applied['listed'])}"}]
    s.add(imp)
    s.flush()
    ledger.append(s, "airgap", imp.id, {"event": "bundle_imported", "version": m["version"], "keyId": m["keyId"],
                                        "sha256": imp.sha256, "applied": applied, "by": by})
    return imp


def import_out(i: models.BundleImport) -> dict:
    return {"id": i.id, "version": i.version, "sha256": i.sha256, "keyId": i.key_id, "status": i.status, "steps": i.steps,
            "applied": i.applied, "importedBy": i.imported_by, "createdAt": i.created_at.isoformat()}


def release_sbom(s: Session) -> dict:
    """제품 자체 릴리스 SBOM (SCR-R05 #8) — 설치된 의존성 + 활성 에이전트(매니페스트 해시)."""
    agents = [{"id": a.id, "version": a.version,
               "sha256": bundle_fmt.sha256(json.dumps(a.manifest, sort_keys=True, ensure_ascii=False).encode())}
              for a in s.scalars(select(models.Agent).where(models.Agent.status.in_(("active", "alert_only"))))]
    sbom = bundle_fmt.product_sbom("0.1.0", agents)
    return {"sbom": sbom, "vulnGate": bundle_fmt.vuln_gate(sbom, vulndb())}
