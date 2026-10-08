"""Epic 52 — 백업 외부 복사 (NFR-A5): 스트림 봉투 암호화 왕복·변조·옮김 탐지·복사·정리·복원. 가짜 S3(메모리).

실제 SeaweedFS(S3 SigV4·상호 TLS)·객체 저장만으로 복구 훈련은 prod 리허설에서 한다.
"""
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.exceptions import InvalidTag

from app import offsite
from app.core.config import settings

STORE: dict[str, bytes] = {}
SEEN_AUTH: list[str] = []


class FakeS3(BaseHTTPRequestHandler):
    def _key(self):
        u = urllib.parse.urlsplit(self.path)
        parts = urllib.parse.unquote(u.path).lstrip("/").split("/", 1)
        return parts[1] if len(parts) > 1 else "", urllib.parse.parse_qs(u.query)

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        SEEN_AUTH.append(self.headers.get("authorization", ""))
        self._send(200)

    def do_PUT(self):
        key, _ = self._key()
        STORE[key] = self.rfile.read(int(self.headers["content-length"])) if key else b""
        self._send(200)

    def do_GET(self):
        key, q = self._key()
        if key:
            return self._send(200, STORE[key]) if key in STORE else self._send(404)
        prefix = q.get("prefix", [""])[0]
        items = "".join(f"<Contents><Key>{k}</Key><Size>{len(v)}</Size></Contents>" for k, v in sorted(STORE.items()) if k and k.startswith(prefix))
        self._send(200, f"<ListBucketResult>{items}<IsTruncated>false</IsTruncated></ListBucketResult>".encode())

    def do_DELETE(self):
        STORE.pop(self._key()[0], None)
        self._send(204)

    def log_message(self, *_):
        pass


@pytest.fixture
def s3(tmp_path, monkeypatch):
    STORE.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeS3)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(settings, "s3_endpoint", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setattr(settings, "s3_access_key", "AK")
    monkeypatch.setattr(settings, "s3_secret_key", "SK")
    monkeypatch.setattr(settings, "db_backup_keep", 2)
    src = tmp_path / "backup"
    monkeypatch.setattr(offsite, "SRC", src)
    yield src
    srv.shutdown()


def _backup(src, name, start_wal, payload: bytes):
    d = src / "base" / name
    d.mkdir(parents=True)
    (d / "base.tar.gz").write_bytes(payload)
    (d / "pg_wal.tar.gz").write_bytes(b"walpart")
    (d / "START_WAL").write_text(start_wal + "\n")


def test_roundtrip_large_file_and_no_plaintext_at_rest(s3, tmp_path):
    marker = b"PLAINTEXT-MARKER-52 " * 400_000                                   # 8 MB → 조각 3개
    f = tmp_path / "big.bin"
    f.write_bytes(marker)
    offsite.ensure_bucket()
    offsite.put_file("base/x/base.tar.gz", f)
    blob = STORE["base/x/base.tar.gz"]
    assert blob.startswith(offsite.MAGIC) and b"PLAINTEXT-MARKER-52" not in blob
    assert len(blob) == offsite._enc_length(blob[:blob.index(b"}") + 1], len(marker))
    assert SEEN_AUTH and SEEN_AUTH[-1].startswith("AWS4-HMAC-SHA256 Credential=AK/")
    out = tmp_path / "out.bin"
    assert offsite.get_file("base/x/base.tar.gz", out) == len(marker) and out.read_bytes() == marker
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    offsite.put_file("wal/e", empty)
    assert offsite.get_file("wal/e", tmp_path / "e2") == 0


def test_tamper_and_moved_object_are_refused(s3, tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"x" * 100)
    offsite.ensure_bucket()
    offsite.put_file("wal/A", f)
    blob = bytearray(STORE["wal/A"])
    blob[-5] ^= 1
    STORE["wal/A"] = bytes(blob)
    with pytest.raises(InvalidTag):
        offsite.get_file("wal/A", tmp_path / "o")
    offsite.put_file("wal/B", f)
    STORE["wal/C"] = STORE["wal/B"]                                                # 다른 키로 옮겨 놓기
    with pytest.raises(offsite.OffsiteError, match="키 불일치"):
        offsite.get_file("wal/C", tmp_path / "o2")


def test_ship_prune_fetch(s3, tmp_path):
    wal = s3 / "wal"
    wal.mkdir(parents=True)
    for seg in ("000000010000000000000001", "000000010000000000000002", "000000010000000000000003", "000000010000000000000004"):
        (wal / seg).write_bytes(seg.encode() * 10)
    _backup(s3, "20261007T000000Z", "000000010000000000000001", b"b1")
    _backup(s3, "20261007T010000Z", "000000010000000000000002", b"b2")
    (s3 / "base" / "20261007T020000Z.partial").mkdir()                            # 진행 중 백업은 올리지 않는다
    r = offsite.ship()
    assert r["uploaded"] == 4 + 6 and r["remoteBackups"] == 2                     # WAL 4 + 백업 2 × 파일 3
    assert offsite.ship()["uploaded"] == 0                                        # 이미 있는 것은 건너뜀
    _backup(s3, "20261007T030000Z", "000000010000000000000003", b"b3")
    r = offsite.ship()                                                            # 보관 2개 → 가장 오래된 백업과 그 앞 WAL 정리
    ks = offsite.keys()
    assert offsite._backups(ks) == ["20261007T010000Z", "20261007T030000Z"]
    assert "wal/000000010000000000000001" not in ks and "wal/000000010000000000000002" in ks and r["pruned"] == 3 + 1
    out = offsite.fetch(tmp_path / "restore")
    got = tmp_path / "restore"
    assert out["backup"] == "20261007T030000Z" and (got / "base/20261007T030000Z/base.tar.gz").read_bytes() == b"b3"
    assert sorted(p.name for p in (got / "wal").iterdir()) == ["000000010000000000000003", "000000010000000000000004"]
