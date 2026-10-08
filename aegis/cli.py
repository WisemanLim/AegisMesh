"""aegis CLI (= python -m aegis) — M1 독립 실행 진입점 (PRD §8.4).

  aegis run <agent> --input request.json        # 일회 판정 → Finding JSON
  aegis serve <agent> --protocol rest|mcp|a2a   # 상주 서버 (REST :8080 / MCP stdio / A2A v1.0 서명 AgentCard)
  aegis a2a card <url> [--trust jwks]           # A2A AgentCard 서명 검증 (FR-X01)
  aegis a2a send <url> --text …|--data f.json   # 카드 검증 후 SendMessage (신뢰 고정 없으면 거부)
  aegis list                                    # 로컬 에이전트 목록
  aegis eval <agent>|--all [--update-baseline]  # 골든셋·공격셋·회귀 기준선
  aegis coverage [--stage N]                    # 도식 누락 검증
  aegis verify-bundle <bundle.json>             # 증적 묶음 독립 검증
  aegis keygen --out pub.key                    # 게시자 서명키 생성
  aegis bundle <agent-dir> --key k --key-id id  # 서명된 에이전트 번들(등록 심사 입력)
  aegis airgap build|verify …                   # 폐쇄망 번들 생성·오프라인 검증 (내부 신뢰 저장소)
  aegis sbom check <sbom.json> [--advisories f] [--fail-on high]   # CI 빌드 게이트 (CycloneDX·SPDX JSON → d7-02)

출력 언어: --lang ko|en (없으면 AEGIS_LANG·LANG) — 사람이 읽는 줄만 바꾸고 JSON 은 그대로 (aegis/i18n.py, NFR-C4).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.agent import discover, load_agent
from aegis.i18n import T, detect, say, set_lang
from aegis.schemas import JudgeRequest


def _read_input(src: str) -> JudgeRequest:
    raw = sys.stdin.read() if src == "-" else Path(src).read_text(encoding="utf-8")
    return JudgeRequest.model_validate_json(raw)


def cmd_run(a) -> int:
    f = load_agent(a.agent).judge(_read_input(a.input), a.engine)
    print(json.dumps(f.dump(), ensure_ascii=False))
    return 0


def cmd_serve(a) -> int:
    agent = load_agent(a.agent)
    if a.protocol == "mcp":
        from aegis.adapters.mcp import serve_stdio
        serve_stdio(agent)
    elif a.protocol == "a2a":
        import uvicorn

        from aegis.adapters import a2a
        url = a.public_url or f"http://localhost:{a.port}"
        key = a2a.load_key(a.key)
        app = a2a.create_app(agent, key, url, a.trust_jwks, a.audience)
        say(f"A2A {a2a.PROTOCOL_VERSION} · {url}{a2a.CARD_PATH} · {T('서명 kid', 'signing kid')} {a2a.jwk(key)['kid']}"
            f"{'' if a.key else T(' (임시 키 — 재기동 시 바뀜)', ' (ephemeral key — changes on restart)')}"
            f"{T(' · 호출자 JWT-SVID 검증', ' · caller JWT-SVID verified') if a.trust_jwks else ''}", file=sys.stderr)
        uvicorn.run(app, host=a.host, port=a.port)
    else:
        import uvicorn
        from aegis.adapters.rest import create_app
        uvicorn.run(create_app(agent), host=a.host, port=a.port)
    return 0


def cmd_list(a) -> int:
    for p in discover():
        a_ = load_agent(p)
        s = a_.manifest.spec
        md = a_.manifest.metadata
        say(f"{a_.id:<7} {s.series} {s.gate:<7} {s.isolation} fail_{s.fail_mode:<6} {T(md.name_ko, md.name)}")
    return 0


def cmd_eval(a) -> int:
    from aegis.harness import evaluate, write_baseline
    targets = discover() if a.all else [a.agent]
    failed = 0
    for t in targets:
        ag = load_agent(t)
        rep = evaluate(ag)
        if a.update_baseline:
            write_baseline(ag, rep)
            rep = evaluate(ag)
        fails = rep.failures()
        failed += bool(fails)
        say(f"{'FAIL' if fails else 'PASS'} {ag.id:<7} golden {rep.golden} fp {rep.fp_rate:.3f} · "
            f"attacks {rep.attacks} det {rep.detection_rate:.3f} · p95 {rep.p95_ms:.2f}ms")
        for x in fails:
            say(f"     - {x}")
    return 1 if failed else 0


def cmd_coverage(a) -> int:
    import contextlib
    import io
    sys.argv = ["verify_coverage.py"] + (["--stage", str(a.stage)] if a.stage is not None else [])
    from scripts.verify_coverage import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main()
    for line in buf.getvalue().splitlines():
        say(line)
    return rc


def cmd_verify_bundle(a) -> int:
    from aegis.ledger_verify import verify_bundle
    ok, msg = verify_bundle(json.loads(Path(a.bundle).read_text(encoding="utf-8")))
    say(("OK " if ok else "FAIL ") + msg)
    return 0 if ok else 1


def cmd_keygen(a) -> int:
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    Path(a.out).write_bytes(base64.b64encode(raw))
    Path(a.out).chmod(0o600)
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(json.dumps({"keyFile": a.out, "publicKey": base64.b64encode(pub).decode()}))
    return 0


def cmd_bundle(a) -> int:
    """에이전트 디렉터리 → 서명된 AgentBundle/v1 (등록 심사 R2 입력)."""
    import base64
    import yaml
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis.ledger_verify import canonical
    root = Path(a.dir)
    files = {str(p.relative_to(root)): p.read_text(encoding="utf-8") for p in sorted(root.rglob("*"))
             if p.is_file() and p.name != "agent.yaml" and "__pycache__" not in p.parts}
    manifest = yaml.safe_load((root / "agent.yaml").read_text(encoding="utf-8"))
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(a.key).read_bytes()))
    sig = base64.b64encode(key.sign(canonical({"manifest": manifest, "files": files}))).decode()
    print(json.dumps({"format": "aegismesh.io/AgentBundle/v1", "manifest": manifest, "files": files,
                      "keyId": a.key_id, "signature": sig}, ensure_ascii=False))
    return 0


def cmd_airgap(a) -> int:
    """폐쇄망 번들 생성·오프라인 검증 (FR-P14) — 네트워크 없이 동작."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis import airgap
    if a.action == "build":
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(a.key).read_bytes()))
        m = airgap.build(Path(a.out), key, a.key_id, a.version, not a.no_profiles, [Path(p) for p in a.agent_bundle or []],
                         Path(a.vulndb) if a.vulndb else None)
        print(json.dumps({"out": a.out, "version": m["version"], "components": len(m["components"]), "keyId": m["keyId"]}, ensure_ascii=False))
        return 0
    trust = json.loads(Path(a.trust).read_text(encoding="utf-8"))
    db = json.loads(Path(a.vulndb).read_text(encoding="utf-8")) if a.vulndb else None
    try:
        v = airgap.verify(Path(a.bundle).read_bytes(), trust.get("keys", trust), db)
    except airgap.BundleError as exc:
        say(f"FAIL {exc.step}: {exc.msg}")
        return 1
    for st in v["steps"]:
        say(f"OK   {st['step']}: {st['detail']}")
    return 0


def cmd_a2a(a) -> int:
    """A2A 클라이언트 — 카드 서명부터 검증한다(FR-X01). 신뢰 고정(--trust) 없이 카드 자체 jku 만 맞으면 send 는 거부."""
    import os

    from aegis.adapters import a2a
    try:
        card = a2a.fetch_json(a2a.card_url(a.url))
        keys, how = a2a.trusted_keys(a.trust, card)
        v = a2a.verify_card(card, keys)
        if a.action == "card":
            iface = card.get("supportedInterfaces", [{}])[0]
            say(f"{'OK  ' if v['ok'] else 'FAIL'} {v['detail']} · {T('신뢰', 'trust')} {how}")
            say(f"     {card.get('name')} v{card.get('version')} · {iface.get('protocolBinding')} {iface.get('protocolVersion')} {iface.get('url')}")
            return 0 if v["ok"] and (how == "pinned" or a.allow_unpinned) else 1
        req = json.loads(Path(a.data).read_text()) if a.data else a.text
        out = a2a.send(a.url, req, a.trust, os.environ.get(a.token_env) if a.token_env else None, a.allow_unpinned)
    except (OSError, ValueError, RuntimeError) as exc:
        say(f"FAIL {type(exc).__name__}: {exc}")
        return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0 if "result" in out["response"] else 1


PURL_ECO = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems"}
SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _components(doc: dict) -> list[dict]:
    """CycloneDX(components·purl) 또는 SPDX(packages·externalRefs purl) → [{name, version, ecosystem}]."""
    out = []
    for c in doc.get("components", []):
        purl = str(c.get("purl", ""))
        eco = PURL_ECO.get(purl[4:].split("/", 1)[0], "") if purl.startswith("pkg:") else ""
        out.append({"name": c.get("name", ""), "version": str(c.get("version", "")), "ecosystem": eco})
    for p in doc.get("packages", []):
        purl = next((r.get("referenceLocator", "") for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"), "")
        eco = PURL_ECO.get(purl[4:].split("/", 1)[0], "") if purl.startswith("pkg:") else ""
        out.append({"name": p.get("name", ""), "version": str(p.get("versionInfo", "")), "ecosystem": eco})
    return [c for c in out if c["name"]]


def cmd_sbom(a) -> int:
    """CI 빌드 게이트 — 네트워크 없이 d7-02 로 SBOM 대 권고(OSV 요약·폐쇄망 반입 스냅샷)를 대조, --fail-on 이상이면 exit 1."""
    doc = json.loads(Path(a.file).read_text(encoding="utf-8"))
    comps = _components(doc)
    adv = json.loads(Path(a.advisories).read_text(encoding="utf-8")) if a.advisories else []
    f = load_agent("d7-02").judge(JudgeRequest(gate="offline", artifact={"kind": "sbom", "components": comps}, params={"advisories": adv}))
    hits = [e for e in f.evidence if (e.location or "").startswith("component:")]
    fail = f.verdict != "allow" and SEV.get(f.severity, 0) >= SEV[a.fail_on]
    say(f"{'✗' if fail else '✓'} {len(comps)} components · {len(hits)} vulnerable · worst {f.severity if hits else '-'} "
        f"(fail-on {a.fail_on}) → {'exit 1' if fail else 'exit 0'}")
    for e in hits:
        say(f"  {e.location[10:]}  {e.note}")
    return 1 if fail else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    set_lang(detect(argv))
    for i in range(len(argv) - 1, -1, -1):                              # --lang 은 어느 자리든 — 하위 명령 파서에는 넘기지 않는다
        if argv[i].startswith("--lang="):
            argv.pop(i)
        elif argv[i] == "--lang" and i + 1 < len(argv):
            del argv[i:i + 2]
    ap = argparse.ArgumentParser(prog="aegis", description=T("AegisMesh 에이전트 SDK·운영 CLI", "AegisMesh agent SDK and operations CLI"))
    ap.add_argument("--lang", choices=["ko", "en"], help=T("출력 언어 (기본 AEGIS_LANG·LANG)", "output language (default AEGIS_LANG / LANG)"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run"); p.add_argument("agent"); p.add_argument("--input", required=True)
    p.add_argument("--engine"); p.set_defaults(fn=cmd_run)
    p = sub.add_parser("serve"); p.add_argument("agent"); p.add_argument("--protocol", choices=["rest", "mcp", "a2a"], default="rest")
    p.add_argument("--key", help=T("A2A AgentCard 서명키(aegis keygen 출력) — 없으면 임시 키", "A2A AgentCard signing key (aegis keygen output) — ephemeral if omitted"))
    p.add_argument("--public-url", help=T("카드에 적을 외부 주소 (기본 http://localhost:<port>)", "external URL written in the card (default http://localhost:<port>)"))
    p.add_argument("--trust-jwks", help=T("호출자 JWT-SVID 검증용 JWKS (URL·파일, 예: 플랫폼 /v1/identity/jwks)",
                                          "JWKS to verify caller JWT-SVIDs (URL or file, e.g. platform /v1/identity/jwks)"))
    p.add_argument("--audience", default="aegismesh", help="JWT-SVID aud")
    p.add_argument("--stdio", action="store_true", help=T("MCP 는 stdio 전송(기본)", "MCP uses stdio transport (default)"))
    p.add_argument("--host", default="0.0.0.0"); p.add_argument("--port", type=int, default=8080); p.set_defaults(fn=cmd_serve)
    p = sub.add_parser("list"); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("eval"); p.add_argument("agent", nargs="?"); p.add_argument("--all", action="store_true")
    p.add_argument("--update-baseline", action="store_true"); p.set_defaults(fn=cmd_eval)
    p = sub.add_parser("coverage"); p.add_argument("--stage", type=int); p.set_defaults(fn=cmd_coverage)
    p = sub.add_parser("verify-bundle"); p.add_argument("bundle"); p.set_defaults(fn=cmd_verify_bundle)
    p = sub.add_parser("keygen"); p.add_argument("--out", required=True); p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("bundle"); p.add_argument("dir"); p.add_argument("--key", required=True)
    p.add_argument("--key-id", required=True); p.set_defaults(fn=cmd_bundle)
    p = sub.add_parser("a2a"); asub2 = p.add_subparsers(dest="action", required=True)
    for name in ("card", "send"):
        q = asub2.add_parser(name); q.add_argument("url"); q.add_argument("--trust", help=T("신뢰 고정 JWKS (URL·파일)", "pinned trust JWKS (URL or file)"))
        q.add_argument("--allow-unpinned", action="store_true", help=T("카드 자체 jku 로만 검증된 상대도 허용(TOFU)", "also accept peers verified only by the card's own jku (TOFU)"))
        if name == "send":
            g = q.add_mutually_exclusive_group(required=True); g.add_argument("--text"); g.add_argument("--data", help=T("JudgeRequest JSON 파일", "JudgeRequest JSON file"))
            q.add_argument("--token-env", help=T("Bearer JWT-SVID 를 담은 환경 변수 이름", "name of the environment variable holding the Bearer JWT-SVID"))
        q.set_defaults(fn=cmd_a2a)
    p = sub.add_parser("airgap"); asub = p.add_subparsers(dest="action", required=True)
    b = asub.add_parser("build"); b.add_argument("--out", required=True); b.add_argument("--key", required=True)
    b.add_argument("--key-id", required=True); b.add_argument("--version", default="0.1.0"); b.add_argument("--no-profiles", action="store_true")
    b.add_argument("--agent-bundle", action="append"); b.add_argument("--vulndb"); b.set_defaults(fn=cmd_airgap)
    v = asub.add_parser("verify"); v.add_argument("bundle"); v.add_argument("--trust", required=True); v.add_argument("--vulndb")
    v.set_defaults(fn=cmd_airgap)
    p = sub.add_parser("sbom"); ssub = p.add_subparsers(dest="action", required=True)
    q = ssub.add_parser("check"); q.add_argument("file"); q.add_argument("--advisories", help=T("권고 목록 JSON [{id, package, ecosystem, affected, severity, fixed}]",
                                                                                              "advisory list JSON [{id, package, ecosystem, affected, severity, fixed}]"))
    q.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high"); q.set_defaults(fn=cmd_sbom)
    a = ap.parse_args(argv)
    if a.cmd == "eval" and not (a.all or a.agent):
        ap.error(T("eval: <agent> 또는 --all", "eval: <agent> or --all"))
    return a.fn(a)
