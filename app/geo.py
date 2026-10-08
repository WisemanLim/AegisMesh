"""지오 IP · 불가능한 이동 (Epic 55 · MSG-030) — DB-IP IP to City Lite(CC BY 4.0, https://db-ip.com) 이미지 빌드 고정 판(sha256)으로
IP → 나라·도시·좌표. 실행 중 네트워크 없음.

- 사설망(RFC 1918·CGNAT·루프백·링크 로컬·ULA) = 'private', 예약·문서용 대역·DB 에 없음·DB 없음 = 'unknown' — 둘 다 지오 없이 기존 대역(/24·/48) 규칙.
- 표시 = 나라 · 시도(DB-IP 의 도시는 동 단위라 너무 촘촘). 새 위치: 두 지점 모두 지오가 있으면 나라가 바뀌거나 GEO_SAME_PLACE_KM 밖으로
  옮겼을 때(대도시권 안 대역 변경은 망 전환으로 보고 넘김), 아니면 대역이 다를 때.
- 불가능한 이동: 대권 거리 ≥ GEO_TRAVEL_MIN_KM(도시 수준 DB 오차 흡수) 이고 마지막으로 본 시각부터의 속도 > GEO_TRAVEL_MAX_KMH.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
from datetime import datetime

from app.core.config import settings

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
                                              "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
_db: dict = {"reader": None, "error": None, "meta": None, "path": None}


def _reader():
    if _db["path"] != settings.geoip_db:
        _db.update({"reader": None, "error": None, "meta": None, "path": settings.geoip_db})
        try:
            import maxminddb
            _db["reader"] = maxminddb.open_database(settings.geoip_db)
            meta_path = os.path.join(os.path.dirname(settings.geoip_db), "meta.json")
            if os.path.exists(meta_path):
                with open(meta_path) as f:
                    _db["meta"] = json.load(f)
        except (ImportError, OSError, ValueError) as e:
            _db["error"] = f"지오 IP DB 없음 — {e}"[:200]
    return _db["reader"]


def net_of(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False))


def lookup(ip: str | None) -> dict | None:
    """{kind: public|private|unknown, net, cc?, city?, lat?, lon?}. IP 가 아니면 None."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    out = {"kind": "unknown", "net": net_of(a)}
    if any(a in n for n in PRIVATE):
        return out | {"kind": "private"}
    if not a.is_global:                                               # 문서용·예약 대역 — DB 에 있을 수 없다
        return out
    r = _reader()
    rec = r.get(str(a)) if r is not None else None
    loc = (rec or {}).get("location") or {}
    if loc.get("latitude") is None:
        return out
    city = (((rec.get("city") or {}).get("names") or {}).get("en") or "").split(" (")[0]
    region = next((((s.get("names") or {}).get("en")) for s in rec.get("subdivisions") or [] if (s.get("names") or {}).get("en")), "") or city
    return out | {"kind": "public", "cc": (rec.get("country") or {}).get("iso_code") or "??", "region": region[:40], "city": city[:40],
                  "lat": round(float(loc["latitude"]), 3), "lon": round(float(loc["longitude"]), 3)}


def label(p: dict | None) -> str | None:
    if not p:
        return None
    if p["kind"] == "public":
        return f"{p['cc']} · {p['region']}" if p["region"] else p["cc"]
    return p["kind"]                                                   # private | unknown — 화면이 문구를 붙인다


def km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """대권 거리(하버사인, 지구 반지름 6371 km)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    d = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 2 * 6371 * math.asin(min(1.0, math.sqrt(d)))


def moved(prev_geo: str | None, prev_net: str | None, prev_lat: float | None, prev_lon: float | None, cur: dict | None) -> bool:
    """세션의 묶인 지점(지오 표시·좌표·대역) → 지금 지점이 새 위치인가."""
    if cur is None:
        return False
    if prev_lat is not None and prev_lon is not None and prev_geo and cur["kind"] == "public":
        return prev_geo.split(" · ")[0] != cur["cc"] or km(prev_lat, prev_lon, cur["lat"], cur["lon"]) >= settings.geo_same_place_km
    return bool(prev_net) and cur["net"] != prev_net


def travel(lat: float | None, lon: float | None, seen_at: datetime | None, cur: dict | None, now: datetime) -> dict | None:
    """마지막으로 본 지점·시각 → 지금 지점. 불가능한 이동이면 {km, minutes, kmh}, 아니면 None."""
    if lat is None or lon is None or seen_at is None or not cur or cur["kind"] != "public":
        return None
    dist = km(lat, lon, cur["lat"], cur["lon"])
    sec = max((now - seen_at).total_seconds(), 1.0)
    kmh = dist / (sec / 3600)
    if dist < settings.geo_travel_min_km or kmh <= settings.geo_travel_max_kmh:
        return None
    return {"km": round(dist), "minutes": round(sec / 60, 1), "kmh": round(kmh)}


def status() -> dict:
    r = _reader()
    m = r.metadata() if r is not None else None
    return {"loaded": r is not None, "error": _db["error"], "path": settings.geoip_db, "source": "DB-IP IP to City Lite (CC BY 4.0)",
            "built": datetime.fromtimestamp(m.build_epoch).date().isoformat() if m else None, "nodes": m.node_count if m else None,
            "sha256": (_db["meta"] or {}).get("sha256"), "month": (_db["meta"] or {}).get("month"),
            "samePlaceKm": settings.geo_same_place_km, "travelMaxKmh": settings.geo_travel_max_kmh, "travelMinKm": settings.geo_travel_min_km}
