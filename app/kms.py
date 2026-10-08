"""저장 암호화 (Epic 49 · NFR-D2 증적·설정·시크릿 전 구간 암호화, 키는 외부 관리 시스템 위임) — 봉투 암호화.

- 값마다 AES-256-GCM(데이터 키 DEK). DEK 는 프로세스가 만들고(KMS_DEK_TTL_SEC 마다 새로) KMS 의 KEK 로 포장해 값과 함께 둔다:
  `aegis1.<포장된 DEK>.<nonce+암호문>`. DEK 표가 없으므로 추가 전용 원장과 충돌하지 않는다. 연결 데이터(AAD) = 표·열 이름.
- KMS (KMS_BACKEND): openbao = transit 키(KMS_TRANSIT_KEY, 기본 aegis-kek)로 DEK 포장·해제 — 브로커 토큰은 encrypt·decrypt 만,
  회전은 운영자(scripts/bao_setup.py rotate-kek). builtin = 데이터 디렉터리의 키 고리 파일(버전별 KEK, 비커밋) — 로컬·리허설 대체.
  포장 접두사(vault: · b:)로 어느 KMS 인지 구분 → 백엔드를 바꿔도 옛 값이 열린다.
- KEK 회전: 새 버전이 새 DEK 를 포장하고 옛 버전은 복호화 전용으로 남는다(원장은 고치지 않음). 수정 가능한 표는 rewrap() 으로 다시 암호화.
- 대상: 증적 원장 본문·정책 본문·프로파일 명세·트래픽 표본·골든 표본(EncryptedJSON) · 2단계 OTP 비밀(EncryptedText)
  · 원장 서명 키·SVID 서명 키·세션 서명 비밀 파일(secret_file). JSON 열은 {"_enc": 토큰} 이라 스키마 변경이 없다.
- 기존 평문 행은 그대로 읽는다. 원장은 추가 전용이라 평문 행은 보존기한 삭제(retention)로만 사라진다.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import JSON, String
from sqlalchemy.types import TypeDecorator

from app import openbao
from app.core.config import settings

PREFIX = "aegis1"
_lock = threading.Lock()
_dek: dict | None = None                              # 이 프로세스의 현재 DEK {"key", "wrapped", "at"}
_keys: dict[str, bytes] = {}                          # 포장본 → DEK (해제 캐시, KMS 호출은 DEK 마다 1회)
STATS = {"seal": 0, "open": 0, "wrap": 0, "unwrap": 0}


class KmsError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── builtin 키 고리 (로컬·리허설 대체 KMS) ───────────────────────────
def _keyring() -> dict:
    path = Path(settings.kms_keyring_file)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_new(path, json.dumps({"current": 1, "keys": {"1": _b64(AESGCM.generate_key(256))}}).encode())
    return json.loads(path.read_text())


def _write_new(path: Path, data: bytes) -> bool:
    """처음 만드는 파일 — 임시 파일을 다 쓴 뒤 link 로 배타 생성(다른 프로세스가 반쯤 쓴 파일을 읽지 않게). 이미 있으면 False."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        os.link(tmp, path)
        return True
    except FileExistsError:
        return False
    finally:
        tmp.unlink(missing_ok=True)


def _replace(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    tmp.replace(path)


# ── KEK 로 DEK 포장·해제 ─────────────────────────────────────────
def _wrap(dek: bytes) -> str:
    STATS["wrap"] += 1
    if settings.kms_backend == "openbao":
        try:
            return openbao._call("POST", f"transit/encrypt/{settings.kms_transit_key}", {"plaintext": base64.b64encode(dek).decode()})["data"]["ciphertext"]
        except openbao.BaoError as e:
            raise KmsError(f"KMS(OpenBao transit) 포장 실패 — {e.msg}") from e
    kr = _keyring()
    v = str(kr["current"])
    n = os.urandom(12)
    return f"b:{v}:{_b64(n + AESGCM(_unb64(kr['keys'][v])).encrypt(n, dek, b'aegis-dek'))}"


def _unwrap(wrapped: str) -> bytes:
    key = _keys.get(wrapped)
    if key is not None:
        return key
    STATS["unwrap"] += 1
    if wrapped.startswith("vault:"):
        try:
            key = base64.b64decode(openbao._call("POST", f"transit/decrypt/{settings.kms_transit_key}", {"ciphertext": wrapped})["data"]["plaintext"])
        except openbao.BaoError as e:
            raise KmsError(f"KMS(OpenBao transit) 해제 실패 — {e.msg}") from e
    elif wrapped.startswith("b:"):
        _, v, blob = wrapped.split(":", 2)
        kek = _keyring()["keys"].get(v)
        if kek is None:
            raise KmsError(f"키 고리에 KEK 버전 {v} 없음")
        raw = _unb64(blob)
        key = AESGCM(_unb64(kek)).decrypt(raw[:12], raw[12:], b"aegis-dek")
    else:
        raise KmsError("알 수 없는 DEK 포장 형식")
    _keys[wrapped] = key
    return key


def _current() -> tuple[bytes, str]:
    global _dek
    with _lock:
        if _dek is None or time.time() - _dek["at"] > settings.kms_dek_ttl_sec:
            key = AESGCM.generate_key(256)
            wrapped = _wrap(key)
            _keys[wrapped] = key
            _dek = {"key": key, "wrapped": wrapped, "at": time.time()}
        return _dek["key"], _dek["wrapped"]


def new_data_key() -> tuple[bytes, str]:
    """큰 파일(백업) 스트림 암호화용 새 DEK 와 KMS 포장본 — 값 단위 seal 과 달리 호출자가 직접 쓴다(Epic 52)."""
    key = AESGCM.generate_key(256)
    return key, _wrap(key)


def open_data_key(wrapped: str) -> bytes:
    return _unwrap(wrapped)


def reset() -> None:
    """다음 암호화부터 새 DEK(현재 KEK 버전으로 포장) — KEK 회전 뒤."""
    global _dek
    with _lock:
        _dek = None


def is_sealed(v) -> bool:
    return isinstance(v, str) and v.startswith(PREFIX + ".")


def seal(data: bytes, aad: str) -> str:
    key, wrapped = _current()
    n = os.urandom(12)
    STATS["seal"] += 1
    return f"{PREFIX}.{wrapped}.{_b64(n + AESGCM(key).encrypt(n, data, aad.encode()))}"


def open_(token: str, aad: str) -> bytes:
    _, wrapped, payload = token.split(".")
    raw = _unb64(payload)
    STATS["open"] += 1
    return AESGCM(_unwrap(wrapped)).decrypt(raw[:12], raw[12:], aad.encode())


def kek_of(token: str) -> str:
    """토큰의 DEK 를 포장한 KEK 버전 — 'openbao:v2' · 'builtin:v1'."""
    w = token.split(".")[1]
    return f"openbao:{w.split(':')[1]}" if w.startswith("vault:") else f"builtin:v{w.split(':')[1]}"


# ── 열 타입 (투명 암호화) ─────────────────────────────────────────
class EncryptedJSON(TypeDecorator):
    """JSON 열 — 쓰기는 {"_enc": 토큰}, 읽기는 원래 값. 평문(옛 행)은 그대로 돌려준다."""
    impl = JSON
    cache_ok = True

    def __init__(self, aad: str):
        super().__init__()
        self.aad = aad

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        out = {"_enc": seal(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(), self.aad)}
        if isinstance(value, dict) and value.get("by") == "anonymous":
            out["by"] = "anonymous"              # 익명 행위 집계(거버넌스 SQL)용 상수 — 개인 정보가 아니다
        return out

    def process_result_value(self, value, dialect):
        if isinstance(value, dict) and "_enc" in value:
            return json.loads(open_(value["_enc"], self.aad))
        return value


class EncryptedText(TypeDecorator):
    """문자열 열(비밀) — 토큰으로 저장. 평문(옛 행)은 그대로 돌려준다."""
    impl = String
    cache_ok = True

    def __init__(self, aad: str, length: int = 255):
        super().__init__(length)
        self.aad = aad

    def process_bind_param(self, value, dialect):
        return None if value is None else seal(value.encode(), self.aad)

    def process_result_value(self, value, dialect):
        return open_(value, self.aad).decode() if is_sealed(value) else value


# ── 비밀 파일 (서명 키·세션 비밀) ──────────────────────────────────
def secret_file(path: Path, generate: Callable[[], bytes]) -> bytes:
    """KMS 로 포장해 저장하는 비밀 파일. 없으면 만들고, 옛 평문 파일은 처음 읽을 때 포장본으로 바꾼다."""
    aad = f"file:{path.name}"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = generate()
        if _write_new(path, seal(raw, aad).encode()):
            return raw
    data = path.read_bytes()
    if data.startswith(PREFIX.encode() + b"."):
        return open_(data.decode(), aad)
    _replace(path, seal(data, aad).encode())
    return data


# ── 운영: 상태 · 회전 · 재암호화 ───────────────────────────────────
# (모델, 열 이름) — 수정 가능한 표. 증적 원장은 추가 전용이라 제외(옛 KEK 버전은 복호화 전용으로 남긴다).
def _mutable():
    from app import models
    return [(models.Policy, "body"), (models.Profile, "spec"), (models.Finding, "body"), (models.Approval, "summary"),
            (models.ApprovalDecision, "reason"), (models.TrafficSample, "request"), (models.GoldenSample, "request"),
            (models.User, "totp_secret")]


def _token_of(v) -> str | None:
    if isinstance(v, dict) and "_enc" in v:
        return v["_enc"]
    return v if is_sealed(v) else None


def _raw(v):
    if isinstance(v, str) and v[:1] in "{[":                 # SQLite 는 JSON 열을 문자열로 돌려준다
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _coverage(raw: list) -> dict:
    toks = [_token_of(_raw(v)) for v in raw]
    kek: dict[str, int] = {}
    for tok in filter(None, toks):
        kek[kek_of(tok)] = kek.get(kek_of(tok), 0) + 1
    return {"rows": len(raw), "encrypted": sum(1 for x in toks if x), "byKek": kek}


def status(s, full: bool = False) -> dict:
    """저장값을 열 타입을 거치지 않고 읽어(text SQL) 암호화 여부·KEK 버전을 센다. 증적은 최근 1000건(full=True 면 전체 건수도)."""
    from sqlalchemy import func, select, text

    from app import models
    kr = _keyring() if settings.kms_backend == "builtin" or Path(settings.kms_keyring_file).exists() else None
    recent = [r[0] for r in s.execute(text("SELECT body FROM evidence ORDER BY seq DESC LIMIT 1000")).all()]
    ev = {"recent": _coverage(recent), "records": s.scalar(select(func.count()).select_from(models.Evidence)) or 0}
    if full:
        from app import ledger_rewrap
        ev["plaintextTotal"] = ledger_rewrap.plan(s)["plaintext"]           # 저장 형식으로 판별(JSON 을 풀지 않음) — Epic 57
        ev["encryptedTotal"] = ev["records"] - ev["plaintextTotal"]
    tables = {}
    for m, c in _mutable():                               # 표본 1000행(full=True 면 전 행) + 전체 건수
        q = f"SELECT {c} FROM {m.__tablename__} WHERE {c} IS NOT NULL" + ("" if full else " LIMIT 1000")
        tables[f"{m.__tablename__}.{c}"] = _coverage([r[0] for r in s.execute(text(q)).all()]) | {
            "total": s.scalar(text(f"SELECT count(*) FROM {m.__tablename__} WHERE {c} IS NOT NULL"))}
    files = {p.name: (p.read_bytes()[:7] == PREFIX.encode() + b".") if p.exists() else None
             for p in map(Path, (settings.ledger_key_file, settings.svid_key_file, settings.auth_secret_file))}
    return {"backend": settings.kms_backend, "transitKey": settings.kms_transit_key if settings.kms_backend == "openbao" else None,
            "builtinKek": {"current": kr["current"], "versions": sorted(int(v) for v in kr["keys"])} if kr else None,
            "process": dict(STATS) | {"dekAgeSec": round(time.time() - _dek["at"], 1) if _dek else None, "cachedDeks": len(_keys)},
            "evidence": ev, "tables": tables, "keyFiles": files}


def rotate_builtin() -> int:
    """builtin 키 고리에 새 KEK 버전을 더하고 현재로 삼는다(옛 버전은 복호화 전용으로 유지)."""
    path = Path(settings.kms_keyring_file)
    kr = _keyring()
    v = max(int(x) for x in kr["keys"]) + 1
    kr["keys"][str(v)], kr["current"] = _b64(AESGCM.generate_key(256)), v
    _replace(path, json.dumps(kr).encode())
    reset()
    return v


def rewrap(s, batch: int = 1000) -> dict:
    """수정 가능한 표를 현재 KEK·새 DEK 로 다시 암호화(평문 옛 행 포함). 기본 키 순 묶음 UPDATE(executemany) — 증적 원장은 건드리지 않는다."""
    from sqlalchemy import bindparam, select, update
    reset()
    out = {}
    for model, col in _mutable():
        t = model.__table__
        pk, c = t.c[model.__mapper__.primary_key[0].name], t.c[col]
        stmt = update(t).where(pk == bindparam("_pk")).values({col: bindparam("_v", type_=c.type)})
        last, n = None, 0
        while True:
            q = select(pk, c).where(c.isnot(None)).order_by(pk).limit(batch)
            rows = s.execute(q if last is None else q.where(pk > last)).all()     # 열 타입이 복호화한 값
            if not rows:
                break
            s.execute(stmt, [{"_pk": r[0], "_v": r[1]} for r in rows])          # 다시 쓰며 현재 DEK 로 암호화
            last, n = rows[-1][0], n + len(rows)
        out[f"{t.name}.{col}"] = n
    for f in map(Path, (settings.ledger_key_file, settings.svid_key_file, settings.auth_secret_file)):   # 비밀 파일도 현재 KEK 로
        if f.exists():
            data = f.read_bytes()
            _replace(f, seal(open_(data.decode(), f"file:{f.name}") if data.startswith(PREFIX.encode() + b".") else data,
                             f"file:{f.name}").encode())
            out[f"file:{f.name}"] = 1
    return out


if __name__ == "__main__":                            # make kms-rewrap · 운영 확인
    import sys

    from app import db
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    with db.system_session() as s:
        if cmd == "status":
            out = status(s, full="--full" in sys.argv)
        elif cmd == "rotate":                         # builtin 만 — OpenBao 는 운영자가 transit 키를 회전(scripts/bao_setup.py rotate-kek)
            if settings.kms_backend != "builtin":
                raise SystemExit("KMS_BACKEND=openbao — KEK 회전은 OpenBao 에서: python scripts/bao_setup.py rotate-kek")
            out = {"builtinKek": rotate_builtin()}
        elif cmd == "rewrap":
            out = {"rewrapped": rewrap(s)}
            s.commit()
        else:
            raise SystemExit(__doc__)
    print(json.dumps(out, ensure_ascii=False, default=str))
