"""등록 7단계 중 R1~R5 심사 (PRD §11.3) — 서드파티 에이전트 번들.

번들 형식 aegismesh.io/AgentBundle/v1:
  {format, manifest, files: {"core.py": "...", "engines/<id>.py": "...", "tests/golden/*.jsonl": "...", ...}, keyId, signature}
  signature = Ed25519(canonical({"manifest", "files"}))  — `python -m aegis bundle <dir> --key <key>` 로 만든다.

결과: rejected(R1·R2 실패) · review_hold(R3 정적 심사 위반, R4 격리 환경 없음) · alert_only(R5 품질 미달) · active.
R4 는 L1 샌드박스(app/sandbox.py — 별도 프로세스·rlimit·빈 환경·Landlock·seccomp·감사 훅)에서 골든·공격을 재생한다.
L0·L1 요구 에이전트는 심사·실행 가능, L2·L3 는 런타임이 없어 보류(격리 강등 금지, §8.6). R3 의 import·내장 함수 허용목록은 그대로 1차 방어선.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError
from sqlalchemy.orm import Session

from aegis.ledger_verify import canonical
from aegis.manifest import Manifest
from app import ledger, models, registry
from app.core.config import settings

BUNDLE_FORMAT = "aegismesh.io/AgentBundle/v1"
ALLOWED_EXT = (".py", ".jsonl", ".json", ".yaml", ".yml", ".md")
# 라이선스 5등급 중 상용 제품 기본값에서 제외하는 등급 4 이상 (PRD §10.13)
DENY_LICENSES = ("BUSL", "SSPL", "Elastic", "ELv2", "FSL", "Commons-Clause", "Llama", "CC-BY-NC", "AGPL")
ALLOWED_IMPORTS = {"aegis", "re", "json", "math", "hashlib", "base64", "binascii", "unicodedata", "collections", "fnmatch",
                   "time", "html", "urllib.parse", "dataclasses", "typing", "itertools", "functools", "string", "statistics",
                   "ipaddress", "datetime", "enum", "decimal", "fractions", "difflib", "textwrap", "__future__"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "open", "__import__", "globals", "locals", "vars", "input", "breakpoint",
                   "setattr", "delattr", "memoryview"}
FORBIDDEN_ATTRS = {"__subclasses__", "__globals__", "__builtins__", "__code__", "__class__", "__bases__", "__mro__"}
SECRET = re.compile(r"(sk-(ant-|proj-)?[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                    r"|xox[abprs]-[A-Za-z0-9-]{10,})")


def registry_dir() -> Path:
    return Path(settings.registry_dir)


def bundle_sha(bundle: dict) -> str:
    return hashlib.sha256(canonical({"manifest": bundle.get("manifest"), "files": bundle.get("files")})).hexdigest()


# ── R1 매니페스트·구조 ──────────────────────────────────────────
def r1(s: Session, bundle: dict) -> tuple[bool, str, Manifest | None]:
    try:
        m = Manifest.model_validate(bundle.get("manifest") or {})
    except ValidationError as exc:
        return False, f"매니페스트 스키마 오류: {exc.errors(include_url=False)[0]['msg']}", None
    if not s.get(models.RiskItem, m.item_id):
        return False, f"도식에 없는 항목 {m.item_id}", None
    cur = s.get(models.Agent, m.id)
    if cur is not None and cur.origin == "builtin":
        return False, f"{m.id} 는 내장 에이전트가 담당 (DP1 항목당 에이전트 하나)", None
    files = bundle.get("files") or {}
    for p in files:
        if p.startswith("/") or ".." in Path(p).parts or not p.endswith(ALLOWED_EXT):
            return False, f"허용되지 않는 파일 경로 {p}", None
    t = m.spec.tests
    need = ["core.py", f"engines/{m.spec.engines.default}.py", t.baseline]
    missing = [f for f in need if f not in files]
    for d in (t.golden, t.attacks):
        if not any(p.startswith(d.rstrip("/") + "/") and p.endswith(".jsonl") for p in files):
            missing.append(f"{d}/*.jsonl")
    if missing:
        return False, f"필수 파일 누락 {missing}", None
    return True, "매니페스트·구조 검증 통과", m


# ── R2 서명·출처 ──────────────────────────────────────────────
def r2(s: Session, bundle: dict) -> tuple[bool, str]:
    kid, sig = bundle.get("keyId"), bundle.get("signature")
    if not kid or not sig:
        return False, "서명 없음"
    key = s.get(models.PublisherKey, kid)
    if key is None or not key.active:
        return False, f"신뢰하지 않는 게시자 키 {kid}"
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key)).verify(
            base64.b64decode(sig), canonical({"manifest": bundle["manifest"], "files": bundle["files"]}))
    except (InvalidSignature, ValueError):
        return False, "서명 검증 실패(번들 변조 또는 다른 키)"
    return True, f"게시자 {key.name}({kid}) 서명 검증 통과"


# ── R3 정적 심사 ──────────────────────────────────────────────
def _py_violations(path: str, src: str) -> list[str]:
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError as exc:
        return [f"{path}: 구문 오류 {exc.msg}"]
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods = [("." * node.level) + (node.module or "")]
        else:
            mods = []
        for mod in mods:
            if mod.startswith("."):
                out.append(f"{path}: 상대 import 금지 {mod}")
            elif not any(mod == a or mod.startswith(a + ".") for a in ALLOWED_IMPORTS):
                out.append(f"{path}: 허용되지 않은 import {mod}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            out.append(f"{path}:{node.lineno} 금지 호출 {node.func.id}()")
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRS:
            out.append(f"{path}:{node.lineno} 금지 속성 {node.attr}")
    return out


def r3(m: Manifest, bundle: dict) -> tuple[bool, str, list[str]]:
    issues = []
    for e in m.spec.engines.available:
        if e.license and any(d.lower() in e.license.lower() for d in DENY_LICENSES):
            issues.append(f"엔진 {e.id} 라이선스 {e.license} — 등급 4 이상(상용 기본값 제외)")
    attacks = m.spec.tests.attacks.rstrip("/") + "/"
    for p, src in bundle["files"].items():
        # 공격 코퍼스는 탐지 시험을 위해 자격증명 '형태' 문자열을 담는 것이 정상이다(D2-03 등) — 비밀 스캔 제외
        if not p.startswith(attacks) and SECRET.search(src):
            issues.append(f"{p}: 자격증명 형태 문자열")
        if p.endswith(".py"):
            issues += _py_violations(p, src)
    return not issues, "정적 심사 통과" if not issues else f"정적 심사 위반 {len(issues)}건 — 사람 검토", issues


# ── R4 격리 시험 (하위 프로세스 재생) ──────────────────────────
def materialize(m: Manifest, bundle: dict, digest: str) -> Path:
    root = registry_dir() / m.id / digest[:16]
    if root.exists():
        shutil.rmtree(root)
    for p, src in bundle["files"].items():
        f = root / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(src, encoding="utf-8")
    (root / "agent.yaml").write_text(yaml.safe_dump(bundle["manifest"], allow_unicode=True, sort_keys=False), encoding="utf-8")
    return root


def _limits():  # 하위 프로세스 자원 한도 (POSIX)
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (settings.review_cpu_sec, settings.review_cpu_sec))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))


def r4(m: Manifest, path: Path) -> tuple[bool, str, dict | None]:
    """골든·공격 재생을 L1 샌드박스(Landlock·seccomp·rlimit)에서 — L2 요구 에이전트는 L2(gVisor 브로커)에서.
    L1 이 없으면 L0 에이전트만 rlimit 하위 프로세스로."""
    from app import sandbox
    l2 = m.spec.isolation == "L2" and sandbox.available("L2")
    if m.spec.isolation in ("L2", "L3") and not l2:  # 실행 자체가 L2·L3 를 요구 — 낮은 등급 대체 불가(격리 강등 금지 §8.6). OQ2 대체는 L0·L1 에이전트의 시험 환경만
        return False, f"요구 격리 {m.spec.isolation} — 이 설치에 {m.spec.isolation} 실행 환경 없음(격리 강등 금지 §8.6). 보류", None
    l1 = sandbox.available("L1")
    if m.spec.isolation == "L1" and not l1:
        return False, "요구 격리 L1 — 실행 환경 없음(격리 강등 금지 §8.6). 보류", None
    try:
        if l2:
            rc, out, err = sandbox.replay(path, "L2")
        elif l1:
            rc, out, err = sandbox.replay(path)
        else:
            root = Path(__file__).resolve().parent.parent
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(root), "AEGIS_RUNTIME_ISOLATION": "L0",
                   "PYTHONDONTWRITEBYTECODE": "1"}
            cp = subprocess.run([sys.executable, "-m", "app.review_runner", str(path)], cwd=str(root), env=env,
                                capture_output=True, text=True, timeout=settings.review_cpu_sec * 3, preexec_fn=_limits)
            rc, out, err = cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        return False, f"자원 한도 초과로 강제 종료(벽시계 {settings.review_cpu_sec * 3}초)", None
    if rc != 0:
        if rc < 0:
            return False, f"자원 한도 초과로 강제 종료(신호 {-rc}: CPU {settings.review_cpu_sec}초·메모리 768MB 한도)", None
        tail = (err or out).strip().splitlines()[-1:] or ["출력 없음"]
        return False, f"재생 실패: {tail[0][:120]}", None
    rep = json.loads(out.strip().splitlines()[-1])
    where = "L2 샌드박스(gVisor)" if l2 else "L1 샌드박스(Landlock·seccomp)" if l1 else "하위 프로세스(L0)"
    if rep["invalid"]:            # 재생 중 예외·무효 판정 — 관문에서는 한도 없는 API 프로세스에서 실행되므로 보류
        return False, f"재생 중 예외·무효 판정 {len(rep['invalid'])}건 (예: {rep['invalid'][0][:60]})", rep
    if rep["p95Ms"] > m.spec.latency_budget_ms:
        return False, f"재생 p95 {rep['p95Ms']}ms > 지연 예산 {m.spec.latency_budget_ms}ms", rep
    return True, f"골든 {rep['golden']}·공격 {rep['attacks']} 재생 ({where}, p95 {rep['p95Ms']}ms)", rep


# ── R5 품질 판정 ──────────────────────────────────────────────
def r5(m: Manifest, rep: dict) -> tuple[bool, str]:
    th = m.spec.tests.thresholds
    fn = 1 - rep["detectionRate"]
    ok = rep["fpRate"] <= th.get("falsePositiveRate", 0.005) and fn <= th.get("falseNegativeRate", 0.10) \
        and not rep["nondeterministic"] and not rep["invalid"]
    return ok, (f"오탐 {rep['fpRate']:.3f} · 미탐 {fn:.3f} — 기준 충족" if ok
                else f"오탐 {rep['fpRate']:.3f} · 미탐 {fn:.3f} — 기준 미달, 경보 전용으로만 등록")


def submit(s: Session, bundle: dict, by: str) -> tuple[models.AgentReview, models.Agent | None]:
    digest = bundle_sha(bundle)
    stages: dict[str, dict] = {}
    agent_row = None

    def done(outcome: str, m: Manifest | None):
        rv = models.AgentReview(id=f"rev_{secrets.token_hex(6)}", agent_id=(m.id if m else str((bundle.get("manifest") or {}).get("metadata", {}).get("id", "?")))[:8],
                                version=m.metadata.version if m else "?", bundle_sha256=digest, outcome=outcome,
                                stages=stages, submitted_by=by)
        s.add(rv)
        s.flush()
        ledger.append(s, "agent", rv.agent_id, {"event": "reviewed", "review": rv.id, "outcome": outcome, "bundleSha256": digest,
                                                "stages": {k: v["result"] for k, v in stages.items()}, "by": by})
        return rv

    ok, msg, m = r1(s, bundle)
    stages["R1"] = {"result": "passed" if ok else "failed", "detail": msg}
    if not ok:
        return done("rejected", None), None
    ok, msg = r2(s, bundle)
    stages["R2"] = {"result": "passed" if ok else "failed", "detail": msg}
    if not ok:
        return done("rejected", m), None
    ok, msg, issues = r3(m, bundle)
    stages["R3"] = {"result": "passed" if ok else "hold", "detail": msg, "issues": issues}
    outcome = "review_hold" if not ok else None
    if outcome is None:
        path = materialize(m, bundle, digest)
        ok, msg, rep = r4(m, path)
        stages["R4"] = {"result": "passed" if ok else "hold", "detail": msg}
        if not ok:
            outcome = "review_hold"
        else:
            ok5, msg5 = r5(m, rep)
            stages["R5"] = {"result": "passed" if ok5 else "alert_only", "detail": msg5,
                            "metrics": {k: rep[k] for k in ("golden", "attacks", "fpRate", "detectionRate", "p95Ms")}}
            outcome = "active" if ok5 else "alert_only"
            from app import sandbox
            if not sandbox.available("L3"):                             # OQ2 결정 — L3 없으면 L1 대체 + 경보 전용, 차단 승격은 2인 승인
                ran = "L2" if m.spec.isolation == "L2" else "L1" if sandbox.available("L1") else "L0"
                stages["R4"]["isolation"] = {"required": "L3", "ran": ran, "shortfall": True}
                stages["R4"]["detail"] += f" · 격리 미달(L3 없음 → {ran} 대체)"
                if outcome == "active":
                    outcome = "alert_only"
                    stages["R5"]["promotion"] = "격리 미달 — 차단 승격은 2인 승인(POST /v1/agents/{id}:promote)"
            if outcome in ("active", "alert_only"):
                cur = registry_dir() / m.id / "current"
                if cur.is_symlink() or cur.exists():
                    cur.unlink() if cur.is_symlink() else shutil.rmtree(cur)
                cur.symlink_to(path.name)
                if m.spec.isolation in ("L1", "L2"):
                    from app import sandbox
                    sandbox.retire(registry_dir() / m.id)
                    sandbox.warm(path.resolve(), m.spec.isolation)
    stages["R6"] = {"result": "published" if outcome in ("active", "alert_only") else "pending",
                    "detail": f"카탈로그 {m.metadata.name_ko} / {m.metadata.name}"}
    agent_row = s.merge(registry._row(m, "api", outcome))
    s.flush()
    registry.runtime_agent.cache_clear()
    registry.quality.cache_clear()
    return done(outcome, m), agent_row
