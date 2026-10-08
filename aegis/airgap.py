"""폐쇄망 번들 (FR-P14, NFR-C3, SCR-A05·R05) — 외부 네트워크 없이 설치·갱신·서명 검증.

번들 = tar.gz:
  bundle.json   {format, version, kind, createdAt, components:[{path, kind, sha256, size}], sbom: "sbom.cdx.json", keyId, signature}
  sbom.cdx.json CycloneDX 1.5 — 제품 의존성(pypi) + 에이전트 구성요소
  <components>  profiles/*.yaml · agent-bundles/*.json(AgentBundle/v1, 게시자 서명) · vulndb.json(내부 취약점 DB)
서명 = Ed25519(canonical(bundle.json 의 signature 제외)). 검증은 내부 신뢰 저장소 키만 쓴다(외부 조회 없음).

  python -m aegis airgap build --out b.tar.gz --key k --key-id id [--version 1.0.0] [--profiles] [--agent-bundle f.json …] [--vulndb f.json]
  python -m aegis airgap verify b.tar.gz --trust trust.json [--vulndb internal.json]
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import time
import uuid
from importlib import metadata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aegis.ledger_verify import canonical

FORMAT = "aegismesh.io/OfflineBundle/v1"
MAX_BYTES = 50 * 1024 * 1024
KINDS = ("profile", "agent-bundle", "vulndb")
GATE = {"critical": 0, "high": 3}                       # SBOM 취약점 반입 기준 (SCR-A05)
ROOT = Path(__file__).resolve().parent.parent


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _signable(manifest: dict) -> bytes:
    return canonical({k: v for k, v in manifest.items() if k != "signature"})


# ── SBOM ────────────────────────────────────────────────────
def product_sbom(version: str, agents: list[dict] | None = None) -> dict:
    """제품 릴리스 SBOM (CycloneDX 1.5) — 설치된 파이썬 배포판 + 에이전트 구성요소(코드 해시)."""
    comps = []
    for d in sorted(metadata.distributions(), key=lambda d: (d.metadata["Name"] or "").lower()):
        name, ver = d.metadata["Name"], d.version
        if not name:
            continue
        lic = d.metadata.get("License-Expression") or d.metadata.get("License") or ""
        c = {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name.lower()}@{ver}"}
        if lic and len(lic) < 80:
            c["licenses"] = [{"expression": lic}]
        comps.append(c)
    for a in agents or []:
        comps.append({"type": "application", "name": f"aegismesh-agent-{a['id']}", "version": a["version"],
                      "purl": f"pkg:generic/aegismesh-agent-{a['id']}@{a['version']}",
                      "hashes": [{"alg": "SHA-256", "content": a["sha256"]}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "component": {"type": "application", "name": "aegismesh", "version": version}},
            "components": comps}


def vuln_gate(sbom: dict, vulndb: dict) -> dict:
    """SBOM 구성요소를 내부 취약점 DB 와 대조 (정확한 버전 목록 일치). critical 0 · high ≤3 초과 시 차단."""
    idx: dict[str, list[dict]] = {}
    for v in vulndb.get("vulnerabilities", []):
        idx.setdefault(v["package"].lower(), []).append(v)
    hits = []
    for c in sbom.get("components", []):
        purl = (c.get("purl") or "").split("@")[0].lower()
        for v in idx.get(purl, []):
            if c.get("version") in v.get("versions", []):
                hits.append({"id": v["id"], "package": purl, "version": c["version"], "severity": v["severity"],
                             "summary": v.get("summary", "")})
    counts = {s: sum(h["severity"] == s for h in hits) for s in ("critical", "high", "medium", "low")}
    ok = counts["critical"] <= GATE["critical"] and counts["high"] <= GATE["high"]
    return {"ok": ok, "counts": counts, "hits": hits, "gate": GATE, "dbVersion": vulndb.get("version")}


# ── 생성 ────────────────────────────────────────────────────
def build(out: Path, key: Ed25519PrivateKey, key_id: str, version: str, profiles: bool = True,
          agent_bundles: list[Path] | None = None, vulndb: Path | None = None, kind: str = "release") -> dict:
    files: dict[str, bytes] = {}
    comps = []

    def add(path: str, kind_: str, data: bytes):
        files[path] = data
        comps.append({"path": path, "kind": kind_, "sha256": sha256(data), "size": len(data)})

    if profiles:
        for f in sorted((ROOT / "profiles").glob("*.yaml")):
            add(f"profiles/{f.name}", "profile", f.read_bytes())
    agents = []
    for p in agent_bundles or []:
        data = Path(p).read_bytes()
        b = json.loads(data)
        add(f"agent-bundles/{b['manifest']['metadata']['id']}-{b['manifest']['metadata']['version']}.json", "agent-bundle", data)
        agents.append({"id": b["manifest"]["metadata"]["id"], "version": b["manifest"]["metadata"]["version"], "sha256": sha256(data)})
    if vulndb:
        add("vulndb.json", "vulndb", Path(vulndb).read_bytes())
    sbom = json.dumps(product_sbom(version, agents), ensure_ascii=False, indent=1).encode()
    files["sbom.cdx.json"] = sbom
    manifest = {"format": FORMAT, "version": version, "kind": kind, "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "components": comps, "sbom": {"path": "sbom.cdx.json", "sha256": sha256(sbom)}, "keyId": key_id}
    manifest["signature"] = base64.b64encode(key.sign(_signable(manifest))).decode()
    with tarfile.open(out, "w:gz") as tar:
        for name, data in [("bundle.json", json.dumps(manifest, ensure_ascii=False, indent=1).encode())] + list(files.items()):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o644
            tar.addfile(ti, io.BytesIO(data))
    return manifest


# ── 검증 ────────────────────────────────────────────────────
class BundleError(ValueError):
    def __init__(self, step: str, msg: str, passed: list[dict] | None = None):
        super().__init__(f"{step}: {msg}")
        self.step, self.msg, self.passed = step, msg, passed or []


def read(data: bytes) -> tuple[dict, dict[str, bytes]]:
    if len(data) > MAX_BYTES:
        raise BundleError("read", f"번들 크기 {len(data)} > {MAX_BYTES}")
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise BundleError("read", f"tar.gz 아님: {exc}") from exc
    files = {}
    with tar:
        for m in tar.getmembers():
            if not m.isfile() or m.name.startswith("/") or ".." in Path(m.name).parts:
                raise BundleError("read", f"허용하지 않는 항목 {m.name}")       # 경로 탈출·링크 금지
            files[m.name] = tar.extractfile(m).read()
    if "bundle.json" not in files:
        raise BundleError("read", "bundle.json 없음")
    manifest = json.loads(files.pop("bundle.json"))
    if manifest.get("format") != FORMAT:
        raise BundleError("read", f"알 수 없는 형식 {manifest.get('format')}")
    return manifest, files


def verify(data: bytes, trust: dict[str, str], vulndb: dict | None = None) -> dict:
    """신뢰 저장소 {keyId: base64 공개키} 로 서명·구성요소 해시·SBOM·취약점 기준을 단계별로 검증.
    한 단계라도 실패하면 BundleError (반입 중단)."""
    manifest, files = read(data)
    steps = []
    kid = manifest.get("keyId")
    if kid not in trust:
        raise BundleError("signature", f"신뢰 저장소에 없는 키 {kid} — 반입 거부 (MSG-005)")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(trust[kid])).verify(
            base64.b64decode(manifest.get("signature", "")), _signable(manifest))
    except (InvalidSignature, ValueError) as exc:
        raise BundleError("signature", "매니페스트 서명 불일치 — 반입 거부 (MSG-005)") from exc
    steps.append({"step": "signature", "ok": True, "detail": f"keyId {kid} (내부 신뢰 저장소)"})
    listed = {c["path"] for c in manifest["components"]} | {manifest["sbom"]["path"]}
    if extra := sorted(set(files) - listed):
        raise BundleError("hash", f"매니페스트에 없는 파일 {extra}", steps)
    for c in manifest["components"] + [manifest["sbom"]]:
        if c["path"] not in files or sha256(files[c["path"]]) != c["sha256"]:
            raise BundleError("hash", f"구성요소 해시 불일치 {c['path']} — 해당 구성요소 반입 거부", steps)
        if c.get("kind") and c["kind"] not in KINDS:
            raise BundleError("hash", f"알 수 없는 구성요소 종류 {c['kind']}", steps)
    steps.append({"step": "hash", "ok": True, "detail": f"구성요소 {len(manifest['components'])} + SBOM 해시 일치"})
    sbom = json.loads(files[manifest["sbom"]["path"]])
    if sbom.get("bomFormat") != "CycloneDX":
        raise BundleError("sbom", "CycloneDX SBOM 아님", steps)
    db = vulndb or {"vulnerabilities": []}
    bundled = next((json.loads(files[c["path"]]) for c in manifest["components"] if c["kind"] == "vulndb"), None)
    if bundled and str(bundled.get("version", "")) > str(db.get("version", "")):
        db = bundled                                      # 서명 검증된 번들의 더 새 취약점 DB
    gate = vuln_gate(sbom, db)
    if not gate["ok"]:
        raise BundleError("sbom", f"SBOM 취약점 기준 초과 {gate['counts']} (critical ≤{GATE['critical']} · high ≤{GATE['high']})", steps)
    steps.append({"step": "sbom", "ok": True, "detail": f"CycloneDX {len(sbom['components'])}개 · 취약점 {gate['counts']} · DB {gate['dbVersion']}",
                  "gate": gate})
    return {"manifest": manifest, "files": files, "sbom": sbom, "steps": steps, "vulndb": db, "sha256": sha256(data)}
