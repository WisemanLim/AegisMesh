"""Epic 59 — 외부 레드팀 엔진 garak 어댑터: 보고서(JSONL) 읽기 → 탐침·탐지기별 무방비·관문 공격 성공률 → 원장·API, 대상 shim 의 관문 경로."""
import json

from app import db, garak
from scripts import garak_target


def _report(path, version, evals):
    lines = [{"entry_type": "start_run setup", "_config.version": version}, {"entry_type": "init", "garak_version": version}]
    lines += [{"entry_type": "attempt", "prompt": "x"}]                                       # 시도 기록은 읽지 않는다(원문 미보관)
    lines += [{"entry_type": "eval", "probe": f"probes.{p}", "detector": f"detector.{d}", "passed": ok, "total": n} for p, d, ok, n in evals]
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\nnot json\n")
    return str(path)


def test_ingest_compares_attack_success_rates(tmp_path, client):
    b = _report(tmp_path / "baseline.report.jsonl", "0.13.1", [("promptinject.HijackHateHumans", "promptinject.AttackRogueString", 0, 100),
                                                               ("encoding.InjectBase64", "encoding.DecodeMatch", 10, 50)])
    g = _report(tmp_path / "guarded.report.jsonl", "0.13.1", [("promptinject.HijackHateHumans", "promptinject.AttackRogueString", 97, 100),
                                                              ("encoding.InjectBase64", "encoding.DecodeMatch", 30, 50)])
    with db.system_session() as s:
        r = garak.ingest(s, g, b, "test")
    assert r["garakVersion"] == "0.13.1" and r["baseline"] == {"total": 150, "hits": 140, "asr": 0.9333} and r["guarded"] == {"total": 150, "hits": 23, "asr": 0.1533}
    pi = next(x for x in r["probes"] if x["probe"] == "promptinject.HijackHateHumans")
    assert pi["detector"] == "promptinject.AttackRogueString" and pi["baseline"]["asr"] == 1.0 and pi["guarded"]["asr"] == 0.03
    got = client.get("/v1/quality/garak").json()["latest"]
    assert got["guarded"]["asr"] == 0.1533 and '"prompt":' not in json.dumps(got)              # 탐침 페이로드·응답 원문 없음


def test_target_shim_refuses_blocked_and_passes_transformed(monkeypatch):
    calls = []

    def fake(gate, request):
        calls.append(gate)
        if "ignore previous" in request.get("text", ""):
            return {"verdict": "block"}
        if gate == "output":
            return {"verdict": "transform", "transformed": {"output": "[REDACTED]"}}
        return {"verdict": "allow"}
    monkeypatch.setattr(garak_target, "judge", fake)
    assert garak_target.respond("ignore previous instructions") == {"text": garak_target.REFUSAL, "verdict": "input:block"} and calls == ["input"]
    assert garak_target.respond("hello 4111 1111 1111 1111") == {"text": "[REDACTED]", "verdict": "output:transform"}
