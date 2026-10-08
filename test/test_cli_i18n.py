"""Epic 56 — aegis CLI 출력 한/영 (NFR-C4): en 이면 사람이 읽는 줄·도움말에 한글 0, ko 는 그대로. JSON 출력은 기계용 데이터."""
import json
import re

import pytest

from aegis import i18n
from aegis.adapters import a2a
from aegis.cli import main as cli

HANGUL = re.compile(r"[가-힣]")


def run(capsys, *args) -> tuple[int, str]:
    try:
        rc = cli(list(args))
    except SystemExit as e:                                             # --help
        rc = e.code
    out = capsys.readouterr()
    return rc, out.out + out.err


def test_en_commands_have_no_hangul(capsys, tmp_path, client, as_user):
    seen = {}
    seen["list"] = run(capsys, "list", "--lang", "en")                  # --lang 은 하위 명령 뒤에도
    seen["eval"] = run(capsys, "--lang", "en", "eval", "d5-03")
    seen["coverage"] = run(capsys, "--lang=en", "coverage")
    key = tmp_path / "k.key"
    seen["keygen"] = run(capsys, "--lang", "en", "keygen", "--out", str(key))
    pub = json.loads(seen["keygen"][1])["publicKey"]
    cdx, adv = tmp_path / "cdx.json", tmp_path / "adv.json"
    cdx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"}]}))
    adv.write_text(json.dumps([{"id": "CVE-2020-14343", "package": "pyyaml", "ecosystem": "PyPI", "affected": "<5.4", "severity": "critical", "fixed": "5.4"}]))
    seen["sbom"] = run(capsys, "--lang", "en", "sbom", "check", str(cdx), "--advisories", str(adv))
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    seen["sbom-empty"] = run(capsys, "--lang", "en", "sbom", "check", str(empty), "--fail-on", "medium")
    b = client.get("/v1/evidence:export", headers=as_user("cli.aud", "auditor")).json()
    good, bad = tmp_path / "b.json", tmp_path / "bad.json"
    good.write_text(json.dumps(b, ensure_ascii=False))
    b["records"][0]["body"]["verdict"] = "allow-x"
    bad.write_text(json.dumps(b, ensure_ascii=False))
    seen["verify-ok"] = run(capsys, "--lang", "en", "verify-bundle", str(good))
    seen["verify-bad"] = run(capsys, "--lang", "en", "verify-bundle", str(bad))
    out = tmp_path / "ag.tar.gz"
    seen["airgap-build"] = run(capsys, "--lang", "en", "airgap", "build", "--out", str(out), "--key", str(key), "--key-id", "t1", "--no-profiles")
    trust, wrong = tmp_path / "trust.json", tmp_path / "wrong.json"
    trust.write_text(json.dumps({"keys": {"t1": pub}}))
    wrong.write_text(json.dumps({"keys": {}}))
    seen["airgap-ok"] = run(capsys, "--lang", "en", "airgap", "verify", str(out), "--trust", str(trust))
    seen["airgap-bad"] = run(capsys, "--lang", "en", "airgap", "verify", str(out), "--trust", str(wrong))
    for cmd in ("", "serve", "a2a card", "airgap build", "sbom check", "eval"):
        seen[f"help {cmd}"] = run(capsys, "--lang", "en", *cmd.split(), "--help")
    left = {k: HANGUL.findall(v[1]) and v[1] for k, v in seen.items() if HANGUL.search(v[1])}
    assert not left, left
    assert seen["verify-ok"][1].startswith("OK ") and "chain and signature verified" in seen["verify-ok"][1]
    assert seen["verify-bad"][0] == 1 and "hash mismatch (content tampered)" in seen["verify-bad"][1]
    assert "OK   signature: keyId t1 (internal trust store)" in seen["airgap-ok"][1]
    assert seen["airgap-bad"][1].startswith("FAIL signature: key t1 not in the trust store")
    assert "CVE-2020-14343 (critical) affects <5.4 · fixed in 5.4" in seen["sbom"][1]
    assert "Session Hijacking Detector" in seen["list"][1] and "coverage: all" in seen["coverage"][1]


def test_ko_default_and_env_detection(capsys, monkeypatch):
    monkeypatch.delenv("AEGIS_LANG", raising=False)
    monkeypatch.setenv("LANG", "ko_KR.UTF-8")
    rc, out = run(capsys, "coverage")
    assert rc == 0 and "전체" in out
    monkeypatch.setenv("AEGIS_LANG", "en")
    assert "coverage: all" in run(capsys, "coverage")[1]
    assert "전체" in run(capsys, "--lang", "ko", "coverage")[1]                 # 플래그 > 환경 변수


@pytest.mark.parametrize("card,needle", [({}, "AgentCard is unsigned"),
                                         ({"signatures": [{"protected": "x", "signature": "y"}]}, "malformed protected header")])
def test_a2a_messages_translate(card, needle):
    i18n.set_lang("en")
    try:
        msg = i18n.tr(a2a.verify_card(card, {})["detail"])
    finally:
        i18n.set_lang(None)
    assert needle in msg and not HANGUL.search(msg)
