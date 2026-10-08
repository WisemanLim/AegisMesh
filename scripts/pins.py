"""고정 판 갱신 (Epic 58) — 이미지에 굽는 외부 참조 데이터(DB-IP Lite 월간 판·FIDO MDS3 스냅숏)의 다음 판을 정한다.

  python scripts/pins.py resolve OUT.json   # 이미지 빌드(`pins` 스테이지) 안에서만 — 네트워크는 빌드 범위
  python scripts/pins.py apply OUT.json     # Dockerfile 맨 위 전역 ARG(DBIP_MONTH·DBIP_SHA256·FIDO_MDS_SNAPSHOT)를 고쳐 쓴다

DB-IP: 이번 달 파일이 있으면 그 판, 아직 없으면 지난달(매달 1일 공개). 지금 판과 같으면 받지 않는다(해시 그대로).
MDS3: 지금 스냅숏의 nextUpdate 가 지났으면 판 이름을 이번 달로 — 빌드의 MDS 캐시는 판 이름이 같을 때만 재사용하므로 새로 받는다.
표준 라이브러리만. 받은 파일은 해시만 계산하고 버린다.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

DBIP = "https://download.db-ip.com/free/dbip-city-lite-{m}.mmdb.gz"
ARGS = ("DBIP_MONTH", "DBIP_SHA256", "FIDO_MDS_SNAPSHOT")


def _months(today: date) -> list[str]:
    prev = date(today.year - (today.month == 1), 12 if today.month == 1 else today.month - 1, 1)
    return [f"{today:%Y-%m}", f"{prev:%Y-%m}"]


def _sha256(url: str) -> str | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "aegismesh-pins/1"}), timeout=300) as r:
            h = hashlib.sha256()
            for chunk in iter(lambda: r.read(1 << 20), b""):
                h.update(chunk)
            return h.hexdigest()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _mds_next_update(d: str) -> str | None:
    try:
        raw = Path(d, "blob.jwt").read_text().split(".")[1]
        return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))).get("nextUpdate")
    except (OSError, IndexError, ValueError):
        return None


def resolve(out: str, today: date | None = None) -> dict:
    today = today or datetime.now(timezone.utc).date()
    cur = {k: os.environ.get(k, "") for k in ARGS}
    res = dict(cur)
    for m in _months(today):
        if m == cur["DBIP_MONTH"]:
            break                                                       # 지금 판이 최신 — 받지 않는다
        sha = _sha256(DBIP.format(m=m))
        if sha:
            res |= {"DBIP_MONTH": m, "DBIP_SHA256": sha}
            break
    nxt = _mds_next_update(os.environ.get("FIDO_MDS_DIR", "/opt/fido"))
    if nxt is None or today >= date.fromisoformat(nxt):
        res["FIDO_MDS_SNAPSHOT"] = f"{today:%Y-%m}"
    report = {"pins": res, "previous": cur, "changed": sorted(k for k in ARGS if res[k] != cur[k]), "mdsNextUpdate": nxt,
              "resolvedAt": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    Path(out).write_text(json.dumps(report, indent=1))
    print(json.dumps(report))
    return report


def apply(src: str, dockerfile: str = "Dockerfile") -> list[str]:
    pins = json.loads(Path(src).read_text())["pins"]
    text, changed = Path(dockerfile).read_text(), []
    for k in ARGS:
        if not re.fullmatch(r"[0-9a-f]{64}|\d{4}-\d{2}", pins[k] or ""):
            raise SystemExit(f"{k} 값 형식 오류: {pins[k]!r}")
        new, n = re.subn(rf"^ARG {k}=.*$", f"ARG {k}={pins[k]}", text, count=1, flags=re.M)
        if n != 1:
            raise SystemExit(f"Dockerfile 에 전역 ARG {k} 없음")
        if new != text:
            changed.append(k)
        text = new
    Path(dockerfile).write_text(text)
    print(json.dumps({"applied": changed, "pins": pins}))
    return changed


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] in ("resolve", "apply"):
        (resolve if sys.argv[1] == "resolve" else apply)(sys.argv[2])
    else:
        raise SystemExit(__doc__)
