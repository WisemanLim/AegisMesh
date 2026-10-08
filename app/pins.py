"""고정 판 점검 (Epic 58) — 이미지에 구운 외부 참조 데이터(FIDO MDS3·DB-IP Lite)가 낡았는지. 실행 중 네트워크 없음.

낡음: MDS3 = 스냅숏의 nextUpdate 가 지남(또는 스냅숏 없음) · DB-IP = 빌드 날짜가 GEO_MAX_AGE_DAYS(45일) 넘음(또는 DB 없음).
갱신은 `make pins-refresh`(이미지 빌드 안에서 다음 판 확인 → Dockerfile 전역 ARG) → 재빌드. worker 가 매일 점검해 낡으면 알림.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from app import fido, geo

GEO_MAX_AGE_DAYS = 45


def check(today: date | None = None) -> dict:
    today = today or datetime.now(timezone.utc).date()
    m, g = fido.status(), geo.status()
    age = (today - date.fromisoformat(g["built"])).days if g.get("built") else None
    items = [
        {"name": "fido-mds3", "loaded": m["loaded"], "version": f"no {m['no']}" if m.get("no") else None, "nextUpdate": m.get("nextUpdate"),
         "fetchedAt": m.get("fetchedAt"), "stale": not m["loaded"] or bool(m.get("stale")), "error": m.get("error")},
        {"name": "dbip-city-lite", "loaded": g["loaded"], "version": g.get("month"), "built": g.get("built"), "ageDays": age,
         "stale": not g["loaded"] or age is None or age > GEO_MAX_AGE_DAYS, "error": g.get("error")},
    ]
    return {"items": items, "stale": [i["name"] for i in items if i["stale"]], "refresh": "make pins-refresh → make prod-build",
            "maxAgeDays": GEO_MAX_AGE_DAYS}
