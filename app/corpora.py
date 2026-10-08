"""공개 공격 코퍼스 실측 (Epic 43 · NFR-Q2·NFR-Q1 · R01) — 이미지 빌드로 받은 고정 판(`infra/corpus`, /corpora)을 오프라인 재생한다.

- 무결성: /corpora/SHA256SUMS 와 파일 해시가 다르면 실행하지 않는다. 출처 커밋·라이선스는 /corpora/PROVENANCE.
- 공격(주입·탈옥) = JailbreakBench 공격 산출물 · garak(DAN·야생 탈옥·TAP·시스템 프롬프트 추출) → 미탐률(NFR-Q2 목표 대상).
- 유해 요청(기법 없음) = HarmBench 행동 · XSTest 위험 질문 → D1 탐지 대상 밖이라 참고로만 보고(scope harmful-request).
- 정상 = XSTest 안전 질문(겉보기 위험, 어려운 정상) · GSM8K 시험셋 → 오탐률.
- 변형 = rules-only(분류기 끈 규칙 전용 엔진) · dual(배포 기본 = 규칙 + 분류기) · deep(+ 응답 후 안전 분류 모델, GUARD_URL 있을 때)
  × 배치 = direct(사용자 입력) · indirect(신뢰할 수 없는 웹 조각).
- 원장에는 해시·건수·범주별 비율·놓친 ID 만 남는다(페이로드 미보존). 분류기 학습에는 쓰지 않는다(OQ4).
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from app import quality
from app.core.config import settings


def root() -> Path:
    return Path(settings.corpora_dir)


def available() -> dict | None:
    """반입본 확인 — 없거나 해시가 다르면 None(이유는 reason)."""
    r = root()
    sums = r / "SHA256SUMS"
    if not sums.exists():
        return None
    bad = []
    for line in sums.read_text().splitlines():
        digest, _, rel = line.partition("  ")
        f = r / rel.lstrip("./")
        if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != digest:
            bad.append(rel)
    prov = [dict(zip(("name", "repo", "commit", "license"), x.split())) for x in (r / "PROVENANCE").read_text().splitlines() if x.strip()]
    return {"root": str(r), "files": len(sums.read_text().splitlines()), "integrity": not bad, "mismatch": bad[:5], "provenance": prov}


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        if it["prompt"] and it["prompt"] not in seen:
            seen.add(it["prompt"])
            out.append(it)
    return out


def load() -> list[dict]:
    r = root()
    prov = {p["name"]: p for p in available()["provenance"]}

    def src(name: str) -> tuple[str, str]:
        p = prov[name]
        return f"{p['repo']}@{p['commit'][:12]}", p["license"]

    jbb = []
    for f in sorted((r / "jailbreakbench" / "attack-artifacts").glob("*/*/*.json")):
        method = f.parts[-3]
        if method == "test-artifact":
            continue
        for jb in json.loads(f.read_text()).get("jailbreaks", []):
            if jb.get("prompt"):
                jbb.append({"id": f"{method}:{f.stem}:{jb.get('index')}", "category": method, "prompt": jb["prompt"]})
    g = r / "garak" / "garak" / "data"
    garak = [{"id": f"dan:{f.stem}", "category": "dan", "prompt": json.loads(f.read_text())[0].replace("{generator.name}", "ChatGPT")}
             for f in sorted((g / "dan").glob("*.json"))]
    garak += [{"id": f"itw:{i}", "category": "in-the-wild", "prompt": p} for i, p in enumerate(json.loads((g / "inthewild_jailbreak_llms.json").read_text()))]
    garak += [{"id": f"tap:{i}", "category": "tap", "prompt": p.strip()} for i, p in enumerate((g / "tap" / "tap_jailbreaks.txt").read_text().splitlines()) if p.strip()]
    for fam, ps in json.loads((g / "sysprompt_extraction" / "attacks.json").read_text()).items():
        garak += [{"id": f"sys:{fam}:{i}", "category": f"sysprompt-{fam}", "prompt": p} for i, p in enumerate(ps)]
    hb = [{"id": x["BehaviorID"], "category": x["FunctionalCategory"], "prompt": x["Behavior"]}
          for x in csv.DictReader((r / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv").open(encoding="utf-8"))]
    xs = list(csv.DictReader((r / "xstest" / "xstest_prompts.csv").open(encoding="utf-8")))
    xs_unsafe = [{"id": f"xs:{x['id']}", "category": x["type"], "prompt": x["prompt"]} for x in xs if x["label"] == "unsafe"]
    xs_safe = [{"id": f"xs:{x['id']}", "category": x["type"], "prompt": x["prompt"]} for x in xs if x["label"] == "safe"]
    gsm = [{"id": f"gsm:{i}", "category": "gsm8k", "prompt": json.loads(line)["question"]}
           for i, line in enumerate((r / "gsm8k" / "grade_school_math" / "data" / "test.jsonl").read_text().splitlines()) if line.strip()]
    return [
        {"name": "jailbreakbench", "src": src("jailbreakbench"), "kind": "attack", "scope": "injection", "items": _dedupe(jbb)},
        {"name": "garak", "src": src("garak"), "kind": "attack", "scope": "injection", "items": _dedupe(garak)},
        {"name": "harmbench", "src": src("harmbench"), "kind": "attack", "scope": "harmful-request", "items": _dedupe(hb)},
        {"name": "xstest-unsafe", "src": src("xstest"), "kind": "attack", "scope": "harmful-request", "items": _dedupe(xs_unsafe)},
        {"name": "xstest-safe", "src": src("xstest"), "kind": "benign", "scope": "injection", "items": _dedupe(xs_safe)},
        {"name": "gsm8k", "src": src("gsm8k"), "kind": "benign", "scope": "injection", "items": _dedupe(gsm)},
    ]


def run(s: Session, by: str, variants: tuple[str, ...] | None = None, modes: tuple[str, ...] = ("direct", "indirect")) -> dict:
    variants = variants or (("rules-only", "dual") + (("deep",) if settings.guard_url else ()) + (("model",) if os.environ.get("INJGUARD_URL") else ()))   # deep = guard · model = injguard(Epic 64)
    a = available()
    if a is None:
        raise quality.QualityError(409, f"공개 코퍼스 반입본 없음 — `make corpus-eval` 이 {root()} 를 채운다")
    if not a["integrity"]:
        raise quality.QualityError(409, f"공개 코퍼스 해시 불일치 — 실행 안 함: {a['mismatch']}")
    rows = []
    for c in load():
        content = "\n".join(json.dumps(it, ensure_ascii=False) for it in c["items"])
        for variant in variants:
            for mode in modes:
                if variant == "deep" and mode == "indirect":
                    continue                      # 깊은 검사는 사용자 입력(text)만 본다 — 간접 배치는 입력이 고정 요약 요청이라 의미 없음
                r = quality.corpus_eval(s, by, f"{c['name']}·{variant}·{mode}", c["src"][0], c["src"][1], "jsonl", content, mode,
                                        c["kind"], variant, c["scope"])
                s.commit()                            # 긴 실측(깊은 검사 수십 분)이 중간에 끊겨도 끝난 행은 원장에 남긴다
                rows.append({"corpus": c["name"], "kind": c["kind"], "scope": c["scope"], "variant": variant, "mode": mode,
                             "items": r["items"], "rate": r.get("missRate", r.get("fpRate")), "ok": r["ok"], "seq": r["seq"],
                             "byCategory": r["byCategory"][:6], "ms": r["durationMs"]})
    return {"provenance": a["provenance"], "rows": rows}


if __name__ == "__main__":                       # make corpus-eval
    from app import db
    with db.system_session() as s:
        args = sys.argv[1:]                         # [변형,…] [방식,…] — 예: dual,model direct
        out = run(s, "corpus-eval", tuple(args[0].split(",")) if args else None, tuple(args[1].split(",")) if len(args) > 1 else ("direct", "indirect"))
        s.commit()
    for p in out["provenance"]:
        print(f"source {p['name']}: {p['repo']}@{p['commit'][:12]} ({p['license']})")
    print(f"{'corpus':<16}{'kind':<8}{'scope':<17}{'variant':<12}{'mode':<10}{'n':>6} {'rate':>8}  by category")
    for r in out["rows"]:
        label = "miss" if r["kind"] == "attack" else "FP"
        cats = " · ".join(f"{x['category']} {x.get('missRate', x.get('fpRate')):.0%}" for x in r["byCategory"][:4])
        print(f"{r['corpus']:<16}{r['kind']:<8}{r['scope']:<17}{r['variant']:<12}{r['mode']:<10}{r['items']:>6} {label} {r['rate']:>6.1%}  {cats}")
    sys.exit(0)
