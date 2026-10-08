"""Epic 55 — 지오 IP·불가능한 이동 (MSG-030): 사설망·미확인 분류, 같은 도시 안 망 전환 통과, 새 도시 재인증, 세션 안·세션 사이 불가능한 이동 →
재인증·D5-03 경보·원장. 가짜 DB 로 시험하고, 이미지에 구운 DB-IP Lite 가 있으면 그것도 확인한다.
"""
import os
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from test_login_hardening import PW, DpopKey, call, login

from app import db, geo, models
from app.auth import utcnow
from app.core.config import settings

SEOUL, SEOUL2, BUSAN, US, LONDON = "211.234.10.20", "211.234.99.1", "175.223.1.1", "8.8.8.8", "81.2.69.160"
RECS = {SEOUL: ("KR", "Seoul", "Yongsan-dong (Hangang-daero)", 37.538, 126.97), SEOUL2: ("KR", "Gyeonggi-do", "Seongnam-si (Buljeong-ro)", 37.365, 127.122),
        BUSAN: ("KR", "Busan", "Jung-gu", 35.18, 129.075), US: ("US", "California", "Mountain View", 37.422, -122.085),
        LONDON: ("GB", "England", "London", 51.509, -0.126)}


class FakeDb:
    def get(self, ip):
        r = RECS.get(ip)
        return {"country": {"iso_code": r[0]}, "subdivisions": [{"names": {"en": r[1]}}], "city": {"names": {"en": r[2]}},
                "location": {"latitude": r[3], "longitude": r[4]}} if r else None

    def metadata(self):
        return SimpleNamespace(build_epoch=1790812800, node_count=123)


@pytest.fixture
def fake_geo(monkeypatch):
    monkeypatch.setattr(geo, "_reader", lambda: FakeDb())


def test_lookup_classification_distance_and_thresholds(fake_geo):
    assert geo.lookup("10.1.2.3") == {"kind": "private", "net": "10.1.2.0/24"}
    assert geo.lookup("100.64.7.7")["kind"] == "private"                          # CGNAT
    assert geo.lookup("203.0.113.9") == {"kind": "unknown", "net": "203.0.113.0/24"}   # 문서용 대역 = 미확인(대역 규칙)
    assert geo.lookup("1.2.3.4")["kind"] == "unknown" and geo.lookup("nope") is None   # DB 에 없음
    seoul, us, busan = geo.lookup(SEOUL), geo.lookup(US), geo.lookup(BUSAN)
    assert geo.label(seoul) == "KR · Seoul" and seoul["city"] == "Yongsan-dong" and geo.label(geo.lookup("10.0.0.1")) == "private"
    assert 9000 < geo.km(seoul["lat"], seoul["lon"], us["lat"], us["lon"]) < 9200 and 15 < geo.km(37.538, 126.97, 37.365, 127.122) < 30
    now = utcnow()
    assert geo.travel(seoul["lat"], seoul["lon"], now - timedelta(minutes=1), busan, now) is None      # 325 km < 최소 거리
    t = geo.travel(seoul["lat"], seoul["lon"], now - timedelta(minutes=10), us, now)
    assert t and t["kmh"] > 50000 and t["minutes"] == 10.0
    assert geo.travel(seoul["lat"], seoul["lon"], now - timedelta(hours=12), us, now) is None           # 12시간 = 비행 가능
    assert geo.moved("KR · Seoul", "211.234.10.0/24", 37.538, 126.97, geo.lookup(SEOUL2)) is False      # 대도시권(≈20 km) 망 전환
    assert geo.moved("KR · Seoul", "211.234.10.0/24", 37.538, 126.97, busan) is True                    # 325 km
    assert geo.moved("private", "10.1.2.0/24", None, None, geo.lookup("10.1.9.9")) is True               # 사설망 = 대역 규칙
    assert geo.moved("private", "10.1.2.0/24", None, None, geo.lookup("10.1.2.200")) is False


def _ev(user, event):
    with db.system_session() as s:
        return [e.body for e in s.scalars(select(models.Evidence).where(models.Evidence.kind == "auth").order_by(models.Evidence.seq))
                if e.body.get("user") == user and e.body.get("event") == event]


def test_same_city_switch_passes_new_city_reauths(fake_geo, anon, as_user):
    as_user("geo.city", "security_engineer")
    k = DpopKey()
    tok = login(anon, "geo.city", k, ip=SEOUL).json()["token"]
    assert call(anon, "GET", "/v1/policies", tok, k, ip=SEOUL).status_code == 200
    assert call(anon, "GET", "/v1/policies", tok, k, ip=SEOUL2).status_code == 200                  # 대도시권 안 다른 시도·대역 — 통과
    cur = next(x for x in call(anon, "GET", "/v1/auth/sessions", tok, k, ip=SEOUL2).json()["items"] if x["current"])
    assert cur["geo"] == "KR · Gyeonggi-do" and cur["location"] == "211.234.99.0/24"
    r = call(anon, "GET", "/v1/policies", tok, k, ip=BUSAN)
    assert r.status_code == 401 and "reauth_required" in r.text and "⌖ KR · Gyeonggi-do → KR · Busan" in r.text
    assert _ev("geo.city", "session_anomaly")[-1]["reason"] == "⌖ KR · Gyeonggi-do → KR · Busan"


def test_impossible_travel_within_session(fake_geo, anon, as_user):
    as_user("geo.fly", "security_engineer")
    k = DpopKey()
    tok = login(anon, "geo.fly", k, ip=SEOUL).json()["token"]
    assert call(anon, "GET", "/v1/policies", tok, k, ip=SEOUL).status_code == 200
    r = call(anon, "GET", "/v1/policies", tok, k, ip=US)
    assert r.status_code == 401 and "✈ KR · Seoul → US · California" in r.text
    ev = _ev("geo.fly", "impossible_travel")[-1]
    assert ev["km"] > 9000 and ev["kmh"] > settings.geo_travel_max_kmh and ev["verdict"] == "alert" and ev["incidents"] == []   # 경보 = 발견만(사건은 차단 판정)
    with db.system_session() as s:
        f = s.scalars(select(models.Finding).where(models.Finding.rule_id == "D5-03.impossible-travel")).first()
        assert f is not None and f.verdict == "alert"
    ok = call(anon, "POST", "/v1/auth/reauth", tok, k, json_={"password": PW}, ip=US).json()
    assert ok["ok"] and ok["location"] == "8.8.8.0/24"
    assert call(anon, "GET", "/v1/policies", tok, k, ip=US).status_code == 200
    assert call(anon, "GET", "/v1/auth/me", tok, k, ip=US).json()["binding"]["geo"] == "US · California"


def test_impossible_travel_across_sessions_at_login(fake_geo, anon, as_user):
    as_user("geo.two", "security_engineer")
    ka, kb = DpopKey(), DpopKey()
    a = login(anon, "geo.two", ka, ip=SEOUL).json()["token"]
    assert call(anon, "GET", "/v1/policies", a, ka, ip=SEOUL).status_code == 200
    b = login(anon, "geo.two", kb, ip=LONDON).json()["token"]                                        # 몇 초 뒤 런던에서 로그인
    r = call(anon, "GET", "/v1/policies", b, kb, ip=LONDON)
    assert r.status_code == 401 and "✈ KR · Seoul → GB · England" in r.text
    ev = _ev("geo.two", "impossible_travel")[-1]
    assert ev["previous"] and ev["km"] > 8000
    assert call(anon, "GET", "/v1/policies", a, ka, ip=SEOUL).status_code == 200                    # 서울 세션은 그대로(판단은 경보·새 세션 재인증)
    with db.system_session() as s:                                                                   # 13시간 전 서울 → 런던 = 비행 가능
        for row in s.scalars(select(models.AuthSession).where(models.AuthSession.geo == "KR · Seoul")):
            row.geo_at = utcnow() - timedelta(hours=13)
        for row in s.scalars(select(models.AuthSession).where(models.AuthSession.geo == "GB · England")):
            row.revoked_at = utcnow()
        s.commit()
    c = login(anon, "geo.two", DpopKey(), ip=LONDON).json()["token"]
    with db.system_session() as s:
        assert s.scalars(select(models.AuthSession).where(models.AuthSession.geo == "GB · England", models.AuthSession.revoked_at.is_(None))).one().state == "ok"
    assert c


def test_geoip_status(fake_geo, client):
    st = client.get("/v1/auth/geoip").json()
    assert st["loaded"] and st["nodes"] == 123 and st["travelMaxKmh"] == 900 and st["samePlaceKm"] == 100 and "CC BY 4.0" in st["source"]
    assert client.get("/v1/auth/geoip", params={"ip": SEOUL}).json()["lookup"]["label"] == "KR · Seoul"
    assert client.get("/v1/auth/geoip", params={"ip": "nope"}).json()["lookup"] is None


@pytest.mark.skipif(not os.path.exists("/opt/geoip/dbip-city-lite.mmdb"), reason="이미지에 지오 IP DB 없음")
def test_baked_dbip_lite():
    geo._db["path"] = None
    assert geo.lookup("8.8.8.8")["cc"] == "US" and geo.lookup("168.126.63.1")["cc"] == "KR"
    st = geo.status()
    assert st["loaded"] and st["sha256"] and st["month"]
