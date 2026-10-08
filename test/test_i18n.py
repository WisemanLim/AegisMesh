"""Epic 26 — 보고서 영어 (NFR-C4): 통제 매핑 보고서 JSON·Markdown 이 lang=en 이면 제목·라벨·고지문 영어."""
import re

HAN = re.compile(r"[가-힣]")


def test_report_english(client):
    ko = client.get("/v1/reports/pipa").json()
    en = client.get("/v1/reports/pipa", params={"lang": "en"}).json()
    assert ko["title"] == "개인정보보호법(대한민국)" and en["title"] == "Personal Information Protection Act (Korea)"
    assert en["lang"] == "en" and en["version"] == "current" and not HAN.search(en["disclaimer"])
    assert not [c for c in en["controls"] if HAN.search(c["title"])]
    assert [c["status"] for c in en["controls"]] == [c["status"] for c in ko["controls"]]          # 언어만 다르고 판정은 같다
    md = client.get("/v1/reports/pipa", params={"lang": "en", "format": "md"}).text
    assert md.startswith("# Personal Information Protection Act (Korea) — Control mapping report") and not HAN.search(md)
    for fw in ("eu-ai-act", "nist-ai-rmf", "owasp-llm-2026", "owasp-asi-2026"):
        assert not HAN.search(client.get(f"/v1/reports/{fw}", params={"lang": "en", "format": "md"}).text), fw
    names = {x["id"]: x["title"] for x in client.get("/v1/reports", params={"lang": "en"}).json()["items"]}
    assert names["pipa"] == "Personal Information Protection Act (Korea)"


def test_fp_budget_rows_carry_english_names(client):
    client.post("/v1/judge:batch", json={"gate": "output", "agents": ["d2-03"], "request": {"output": "안녕"}})
    row = next(r for r in client.get("/v1/quality/fp-budget").json()["agents"] if r["agent"] == "d2-03")
    assert row["name"] == "API Key Leak Detector" and row["nameKo"] == "자격증명 유출 탐지기"
