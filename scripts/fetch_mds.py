"""FIDO MDS3 스냅숏 받기 (Epic 54) — 이미지 빌드 때만 실행한다(표준 라이브러리만). 검증은 `python -m app.fido verify` 몫.

출력 DIR: blob.jwt(MDS3 BLOB, JWS) · root-r3.crt(GlobalSign Root CA - R3, DER — 지문은 app.fido 가 고정값과 대조) ·
meta.json {url, fetchedAt, sha256, bytes}. MDS 는 같은 주소가 매달 갱신되고 요청 빈도를 제한(429)하므로 Retry-After 를 지켜 몇 번만 다시 시도.
--cache DIR(BuildKit 캐시 마운트): 같은 판(FIDO_MDS_SNAPSHOT)을 7일 안에 받은 사본이면 다시 받지 않고, 받기에 실패하면 캐시 사본으로 대신한다(검증은 똑같이).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

MDS_URL = os.environ.get("FIDO_MDS_URL") or "https://mds3.fidoalliance.org/"
ROOT_URL = "https://secure.globalsign.com/cacert/root-r3.crt"


FILES = ("blob.jwt", "root-r3.crt", "meta.json")
FRESH_SEC = 7 * 86400


def get(url: str, tries: int = int(os.environ.get("FIDO_MDS_TRIES") or 4)) -> bytes:
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "aegismesh-mds-fetch/1"}), timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or i == tries - 1:
                raise
            try:
                wait = int(e.headers.get("Retry-After") or 0)
            except ValueError:
                wait = 0
            wait = min(wait or 30 * (i + 1), 300)
        except (urllib.error.URLError, TimeoutError):
            if i == tries - 1:
                raise
            wait = 10 * (i + 1)
        print(f"fetch_mds: {url} 다시 시도 {wait}s 뒤", file=sys.stderr)
        time.sleep(wait)
    raise RuntimeError("unreachable")


def _cached(cache: str | None) -> dict | None:
    try:
        with open(os.path.join(cache or "", "meta.json")) as f:
            return json.load(f) if all(os.path.exists(os.path.join(cache, n)) for n in FILES) else None
    except (OSError, ValueError):
        return None


def _copy(src: str, dst: str) -> None:
    os.makedirs(dst, exist_ok=True)
    for n in FILES:
        shutil.copyfile(os.path.join(src, n), os.path.join(dst, n))


def _same_snapshot(meta: dict, label: str) -> bool:
    """캐시 사본이 요청한 판(FIDO_MDS_SNAPSHOT, YYYY-MM)인가 — 판 이름이 없던 옛 사본은 받은 달로 본다."""
    return not label or meta.get("snapshot", meta.get("fetchedAt", "")[:7]) == label


def main(out: str, cache: str | None = None) -> None:
    label = os.environ.get("FIDO_MDS_SNAPSHOT", "")
    hit = _cached(cache)
    if hit and _same_snapshot(hit, label) and time.time() - datetime.fromisoformat(hit["fetchedAt"]).timestamp() < FRESH_SEC:
        _copy(cache, out)
        print(json.dumps(hit | {"source": "cache"}))
        return
    try:
        blob, root = get(MDS_URL), get(ROOT_URL)
    except Exception as e:                                          # noqa: BLE001 — 받기 실패면 캐시 사본(있을 때만)
        if not hit:
            raise
        print(f"fetch_mds: 받기 실패({e}) — {hit['fetchedAt']} 캐시 사본 사용", file=sys.stderr)
        _copy(cache, out)
        print(json.dumps(hit | {"source": "cache-fallback"}))
        return
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "blob.jwt"), "wb") as f:
        f.write(blob)
    with open(os.path.join(out, "root-r3.crt"), "wb") as f:
        f.write(root)
    meta = {"url": MDS_URL, "fetchedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob), "snapshot": label or None}
    with open(os.path.join(out, "meta.json"), "w") as f:
        json.dump(meta, f)
    if cache:
        _copy(out, cache)
    print(json.dumps(meta | {"source": "download"}))


if __name__ == "__main__":
    args = sys.argv[1:]
    cache = args[args.index("--cache") + 1] if "--cache" in args else None
    main(next((a for a in args if not a.startswith("--") and a != cache), "/opt/fido"), cache)
