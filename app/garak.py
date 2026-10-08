"""외부 레드팀 엔진 garak 어댑터 (Epic 59 · 의존성 '탐지 엔진 오픈소스, 교체 가능') — garak 고정 판(infra/garak)이 같은 탐침을
무방비 모델(test.Repeat — 입력을 그대로 되돌림)과 AegisMesh 관문을 거친 같은 모델(garak-target)에 보내고, 그 보고서를 여기서 읽는다.

- 공격 성공률(ASR) = 1 − 통과/전체 (탐침·탐지기 쌍마다). 관문의 효과 = 무방비 ASR 대비 관문 ASR.
- 결과는 원장 quality `garak_scan`(탐침별 무방비·관문 ASR, garak 판) — 페이로드·응답 원문은 보관하지 않는다.

  python -m app.garak setup                      # 서비스 계정 토큰(표준 출력 → infra/garak/target.env) + 보호 대상 garak.demo 에 프로파일 적용
  python -m app.garak ingest GUARDED BASELINE    # 두 보고서(JSONL) → 원장
"""
from __future__ import annotations

import json
import secrets
import sys
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import auth, db, ledger, models, profiles

SERVICE, TARGET, PROFILE = "svc.garak", "garak.demo", "chatbot-baseline"


def setup(s: Session) -> str:
    db.set_scope(s, "*")
    u = s.scalars(select(models.User).where(models.User.username == SERVICE)).first()
    if u is None:
        u = auth.create_user(s, None, SERVICE, "garak 대상(레드팀 엔진)", ["service"], "default", "Gk-" + secrets.token_urlsafe(24))
    u.active = True
    _, tok = auth.issue(s, u, "api_token", "garak-scan", timedelta(hours=6))
    if profiles.active_for(s, "default", TARGET) is None:
        profiles.apply(s, PROFILE, "default", TARGET, "enforce", "garak-setup")
    s.commit()
    return tok


def parse(path: str) -> dict:
    """garak report.jsonl → {version, probes: {(probe, detector): (passed, total)}}."""
    out: dict = {"version": None, "evals": {}}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        t = e.get("entry_type")
        if t in ("init", "start_run setup") and not out["version"]:
            out["version"] = e.get("garak_version") or e.get("_config.version")
        if t == "eval":
            key = (e["probe"].removeprefix("probes."), e["detector"].removeprefix("detector.").removeprefix("detectors."))
            out["evals"][key] = (int(e.get("passed", 0)), int(e.get("total", e.get("total_evaluated", 0))))
    return out


def _asr(passed: int, total: int) -> float | None:
    return round(1 - passed / total, 4) if total else None


def ingest(s: Session, guarded: str, baseline: str, by: str = "garak-scan") -> dict:
    g, b = parse(guarded), parse(baseline)
    rows = []
    for key in sorted(set(g["evals"]) | set(b["evals"])):
        gp, gt = g["evals"].get(key, (0, 0))
        bp, bt = b["evals"].get(key, (0, 0))
        rows.append({"probe": key[0], "detector": key[1], "baseline": {"total": bt, "hits": bt - bp, "asr": _asr(bp, bt)},
                     "guarded": {"total": gt, "hits": gt - gp, "asr": _asr(gp, gt)}})

    def total(side):
        hits = sum(r[side]["hits"] for r in rows)
        n = sum(r[side]["total"] for r in rows)
        return {"total": n, "hits": hits, "asr": round(hits / n, 4) if n else None}
    body = {"event": "garak_scan", "garakVersion": g["version"] or b["version"], "target": TARGET, "profile": PROFILE,
            "baseline": total("baseline"), "guarded": total("guarded"), "probes": rows, "by": by}
    db.set_scope(s, "*")
    ledger.append(s, "quality", "garak", body)
    s.commit()
    return body


def latest(s: Session) -> dict | None:
    r = s.scalars(select(models.Evidence).where(models.Evidence.kind == "quality", models.Evidence.ref_id == "garak")
                  .order_by(models.Evidence.seq.desc()).limit(1)).first()
    return r.body | {"at": r.created_at, "seq": r.seq} if r else None


if __name__ == "__main__":
    with db.system_session() as s:
        if len(sys.argv) == 2 and sys.argv[1] == "setup":
            print(f"# make garak-scan 이 만든다(비커밋) — 서비스 계정 {SERVICE} 토큰(6시간)\nGARAK_AEGIS_TOKEN={setup(s)}\nGARAK_TARGET={TARGET}")
        elif len(sys.argv) == 4 and sys.argv[1] == "ingest":
            r = ingest(s, sys.argv[2], sys.argv[3])
            print(json.dumps({k: r[k] for k in ("garakVersion", "baseline", "guarded")} |
                             {"probes": [(x["probe"], x["detector"], x["baseline"]["asr"], x["guarded"]["asr"]) for x in r["probes"]]}, ensure_ascii=False))
        else:
            raise SystemExit(__doc__)
