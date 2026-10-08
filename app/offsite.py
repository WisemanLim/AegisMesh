"""백업 외부 복사 (Epic 52 · NFR-A5 · 의존성 '객체 저장 SeaweedFS') — 기본 백업·보관 WAL 을 S3 호환 객체 저장으로 암호화해 복사한다.

- 암호화: 파일마다 새 DEK(AES-256-GCM, 4 MB 조각마다 nonce·태그, AAD = 객체 키 + 조각 번호 → 조각 순서 바꿈·잘림 탐지).
  DEK 는 KMS(KMS_BACKEND)가 포장해 객체 머리에 둔다 — 객체 저장에는 평문도 키도 없다. 원문 sha256 으로 복원 후 확인.
- 전송: S3 SigV4(표준 라이브러리만) · 상호 TLS(내부 CA, TLS_DIR 의 api 인증서) · 객체 저장은 S3 만 열고 클라이언트 인증서 필수.
- 배치: base/<백업 이름>/<파일>, wal/<세그먼트>. 완료된 기본 백업(.partial 아님)만, 이미 있는 키는 건너뛴다. 원격 보관은
  최근 DB_BACKUP_KEEP 개 기본 백업과 그중 가장 오래된 것의 WAL 경계 이후 WAL 만 남긴다.
- 복구: fetch 가 최신(또는 지정) 기본 백업과 그 경계 이후 WAL 을 받아 복호화·검증해 /backup 과 같은 배치로 푼다
  → 복구 훈련 서버(db-drill)가 그대로 쓴다(make db-restore-drill ENV=prod SOURCE=offsite).
주의: builtin KMS 키 고리는 appdata 볼륨에 있다 — 호스트를 통째로 잃으면 외부 복사본도 못 연다. 운영은 영속 OpenBao(외부 KMS)를 쓴다.

  python -m app.offsite ship | loop | list | fetch <디렉터리> [백업 이름]
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import http.client
import json
import os
import struct
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import kms, tls
from app.core.config import settings

MAGIC, CHUNK = b"AEGISOFF1", 4 << 20
SRC = Path(os.environ.get("OFFSITE_SRC", "/backup"))
STATS = {"uploaded": 0, "bytes": 0, "skipped": 0, "pruned": 0, "lastShipAt": None, "lastError": None}


class OffsiteError(Exception):
    pass


# ── S3 (SigV4, UNSIGNED-PAYLOAD — 전송은 상호 TLS) ─────────────────
def _conn() -> http.client.HTTPConnection:
    u = urllib.parse.urlsplit(settings.s3_endpoint)
    if u.scheme == "https":
        return http.client.HTTPSConnection(u.hostname, u.port or 443, context=tls.client_context(), timeout=120)
    return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=120)


def _qs(query: dict[str, str]) -> str:
    """서명과 요청이 같은 문자열을 쓰게 — RFC 3986 인코딩, 키 순 정렬."""
    return "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" for k, v in sorted(query.items()))


def _sign(method: str, path: str, query: dict[str, str], headers: dict[str, str]) -> dict[str, str]:
    now = dt.datetime.now(dt.UTC)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = urllib.parse.urlsplit(settings.s3_endpoint).netloc
    h = {k.lower(): v for k, v in headers.items()} | {"host": host, "x-amz-date": amz, "x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    signed = ";".join(sorted(h))
    qs = _qs(query)
    creq = "\n".join([method, urllib.parse.quote(path, safe="/-_.~"), qs, "".join(f"{k}:{h[k].strip()}\n" for k in sorted(h)),
                      signed, "UNSIGNED-PAYLOAD"])
    scope = f"{day}/{settings.s3_region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = f"AWS4{settings.s3_secret_key}".encode()
    for part in (day, settings.s3_region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return h | {"authorization": f"AWS4-HMAC-SHA256 Credential={settings.s3_access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"}


def _req(method: str, key: str = "", query: dict[str, str] | None = None, body=None, length: int | None = None,
         ok: tuple[int, ...] = (200,)) -> http.client.HTTPResponse:
    path = f"/{settings.s3_bucket}" + (f"/{key}" if key else "")
    query = query or {}
    headers = {"content-length": str(length)} if length is not None else {}
    c = _conn()
    target = urllib.parse.quote(path, safe="/-_.~") + ("?" + _qs(query) if query else "")
    c.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
    for k, v in _sign(method, path, query, headers).items():
        c.putheader(k, v)
    c.endheaders()
    if body is not None:
        for chunk in body:
            c.send(chunk)
    r = c.getresponse()
    if r.status not in ok:
        raise OffsiteError(f"S3 {method} {key or settings.s3_bucket} → {r.status} {r.read()[:200]!r}")
    return r


def ensure_bucket() -> None:
    try:
        _req("HEAD", ok=(200,)).read()
    except OffsiteError:
        _req("PUT", length=0, ok=(200,)).read()


def keys(prefix: str = "") -> dict[str, int]:
    out, token = {}, None
    while True:
        q = {"list-type": "2", "prefix": prefix} | ({"continuation-token": token} if token else {})
        root = ET.fromstring(_req("GET", query=q).read())
        ns = {"s": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
        p = "s:" if ns else ""
        for c in root.findall(f"{p}Contents", ns):
            out[c.find(f"{p}Key", ns).text] = int(c.find(f"{p}Size", ns).text)
        if (root.findtext(f"{p}IsTruncated", "false", ns)) != "true":
            return out
        token = root.findtext(f"{p}NextContinuationToken", None, ns)


# ── 스트림 암호화 ───────────────────────────────────────────────
def _header(key: str, size: int, digest: str) -> tuple[bytes, bytes]:
    dek, wrapped = kms.new_data_key()
    h = json.dumps({"v": 1, "key": key, "wrapped": wrapped, "chunk": CHUNK, "size": size, "sha256": digest}).encode()
    return MAGIC + struct.pack(">I", len(h)) + h, dek


def _enc_length(header: bytes, size: int) -> int:
    n = max(1, -(-size // CHUNK))
    return len(header) + size + n * 28


def put_file(key: str, path: Path) -> int:
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            digest.update(b)
    header, dek = _header(key, size, digest.hexdigest())
    aes = AESGCM(dek)

    def body():
        yield header
        with path.open("rb") as f:
            i = 0
            while True:
                b = f.read(CHUNK)
                if not b and i:
                    break
                n = os.urandom(12)
                yield n + aes.encrypt(n, b, f"{key}:{i}".encode())
                i += 1
                if len(b) < CHUNK:
                    break

    total = _enc_length(header, size)
    _req("PUT", key, body=body(), length=total).read()
    STATS["uploaded"] += 1
    STATS["bytes"] += total
    return total


def get_file(key: str, dest: Path) -> int:
    r = _req("GET", key)
    if r.read(len(MAGIC)) != MAGIC:
        raise OffsiteError(f"{key}: 외부 복사 형식 아님")
    h = json.loads(r.read(struct.unpack(">I", r.read(4))[0]))
    if h["key"] != key:
        raise OffsiteError(f"{key}: 머리의 키 불일치(다른 객체를 옮겨 놓음)")
    aes, digest, size, i = AESGCM(kms.open_data_key(h["wrapped"])), hashlib.sha256(), 0, 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with tmp.open("wb") as out:
        while True:
            want = min(h["chunk"], h["size"] - size) + 28
            blob = r.read(want)
            if not blob:
                break
            b = aes.decrypt(blob[:12], blob[12:], f"{key}:{i}".encode())   # 태그 불일치 = 변조·순서 바뀜 → 예외
            out.write(b)
            digest.update(b)
            size, i = size + len(b), i + 1
            if size >= h["size"]:
                break
    if size != h["size"] or digest.hexdigest() != h["sha256"]:
        raise OffsiteError(f"{key}: 크기·해시 불일치(잘림)")
    tmp.replace(dest)
    return size


# ── 복사·정리·복원 ──────────────────────────────────────────────
def _local() -> dict[str, Path]:
    out = {}
    base = SRC / "base"
    for d in sorted(p for p in base.iterdir() if p.is_dir() and not p.name.endswith(".partial")) if base.exists() else []:
        for f in d.iterdir():
            out[f"base/{d.name}/{f.name}"] = f
    for f in sorted((SRC / "wal").iterdir()) if (SRC / "wal").exists() else []:
        if f.is_file():
            out[f"wal/{f.name}"] = f
    return out


def ship() -> dict:
    """아직 없는 객체만 올리고(기본 백업은 START_WAL 을 마지막에 — 완료 표식), 오래된 원격 백업·WAL 을 정리한다."""
    ensure_bucket()
    remote = keys()
    local = _local()
    todo = sorted((k for k in local if k not in remote), key=lambda k: (k.endswith("START_WAL"), k))
    for k in todo:
        put_file(k, local[k])
    STATS["skipped"] += len(local) - len(todo)
    pruned = prune()
    STATS["lastShipAt"], STATS["lastError"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), None
    return {"uploaded": len(todo), "pruned": pruned, "remoteBackups": len(_backups(keys("base/")))}


def _backups(ks: dict[str, int]) -> list[str]:
    """START_WAL 이 올라간(완료된) 원격 기본 백업 이름, 오래된 순."""
    return sorted({k.split("/")[1] for k in ks if k.startswith("base/") and k.endswith("/START_WAL")})


def _start_wal(name: str) -> str:
    tmp = Path(f"/tmp/aegis-offsite-{os.getpid()}-{name}")
    get_file(f"base/{name}/START_WAL", tmp)
    try:
        return tmp.read_text().strip()
    finally:
        tmp.unlink(missing_ok=True)


def prune() -> int:
    ks = keys()
    bs = _backups(ks)
    drop = bs[:-settings.db_backup_keep] if len(bs) > settings.db_backup_keep else []
    gone = [k for k in ks if k.startswith("base/") and k.split("/")[1] in drop]
    keep = [b for b in bs if b not in drop]
    if keep:
        floor = _start_wal(keep[0])
        gone += [k for k in ks if k.startswith("wal/") and k[4:28] < floor[:24]]
    for k in gone:
        _req("DELETE", k, ok=(200, 204)).read()
    STATS["pruned"] += len(gone)
    return len(gone)


def fetch(dest: Path, name: str | None = None) -> dict:
    """최신(또는 지정) 원격 기본 백업 + 그 경계 이후 WAL 을 받아 /backup 배치로 푼다(복구 훈련용)."""
    ks = keys()
    bs = _backups(ks)
    if not bs:
        raise OffsiteError("외부 복사본에 완료된 기본 백업 없음")
    name = name or bs[-1]
    floor = _start_wal(name)
    want = [k for k in ks if k.startswith(f"base/{name}/")] + [k for k in ks if k.startswith("wal/") and k[4:28] >= floor[:24]]
    t0, n = time.perf_counter(), 0
    for k in want:
        n += get_file(k, dest / k)
    return {"backup": name, "objects": len(want), "bytes": n, "sec": round(time.perf_counter() - t0, 1)}


def status() -> dict:
    out = {"endpoint": settings.s3_endpoint, "bucket": settings.s3_bucket} | dict(STATS)
    try:
        ks = keys()
        out |= {"remoteBackups": _backups(ks), "remoteWal": sum(1 for k in ks if k.startswith("wal/")),
                "remoteBytes": sum(ks.values()), "ok": True}
    except (OffsiteError, OSError) as e:
        out |= {"ok": False, "error": str(e)[:200]}
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "loop":                                                   # compose backup-ship — WAL 이 생기는 대로 복사
        while True:
            try:
                r = ship()
                if r["uploaded"] or r["pruned"]:
                    print(json.dumps(r), flush=True)
            except (OffsiteError, OSError) as e:
                STATS["lastError"] = str(e)[:200]
                print(f"offsite 복사 실패 — 다음 주기에 재시도: {e}", flush=True)
            time.sleep(settings.offsite_interval_sec)
    out = {"ship": ship, "status": status}.get(cmd, lambda: None)()
    if cmd == "fetch":
        out = fetch(Path(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else None)
    if out is None:
        raise SystemExit(__doc__)
    print(json.dumps(out, ensure_ascii=False, default=str))
