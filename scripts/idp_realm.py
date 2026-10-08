"""시험 IdP(Keycloak, compose 프로파일 idp) 렐름 생성 — 시험 사용자 비밀번호·TOTP 비밀은 실행 때 만들고 커밋하지 않는다.

  python scripts/idp_realm.py            # infra/keycloak/import/{realm-aegis.json, test-users.env, admin.env} (있으면 유지)
  python scripts/idp_realm.py totp kc.alice   # 현재 TOTP 6자리 (E2E 자동화용, 30초 유효)

사용자: kc.alice(sec-soc) · kc.bob(ciso-office) · kc.chris(garam-admins) · kc.plat(sec-platform) · kc.dave(그룹 없음 → 거부 시험).
Keycloak TOTP 는 비밀 문자열의 UTF-8 바이트를 HMAC 키로 쓴다.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import string
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "infra" / "keycloak" / "import"
USERS = {"kc.alice": ["sec-soc"], "kc.bob": ["ciso-office"], "kc.chris": ["garam-admins"], "kc.plat": ["sec-platform"], "kc.dave": []}


def _var(user: str, kind: str) -> str:
    return f"{user.replace('.', '_').upper()}_{kind}"


def _load() -> dict[str, str]:
    f = OUT / "test-users.env"
    return dict(line.split("=", 1) for line in f.read_text().splitlines() if "=" in line and not line.startswith("#")) if f.exists() else {}


def _write(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o600)


def generate() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if (OUT / "realm-aegis.json").exists() and (OUT / "test-users.env").exists():
        print(f"유지: {OUT.relative_to(ROOT)} (다시 만들려면 디렉터리 삭제)")
        return
    alnum = string.ascii_letters + string.digits
    env, users = {}, []
    for u, groups in USERS.items():
        pw, otp = secrets.token_urlsafe(18), "".join(secrets.choice(alnum) for _ in range(20))
        env[_var(u, "PW")], env[_var(u, "OTP")] = pw, otp
        first = u.split(".")[1].title()
        users.append({"username": u, "enabled": True, "email": f"{u}@aegis.test", "emailVerified": True,
                      "firstName": first, "lastName": "Test", "groups": groups,
                      "credentials": [{"type": "password", "value": pw, "temporary": False},
                                      {"type": "otp", "userLabel": "e2e", "secretData": json.dumps({"value": otp}),
                                       "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30,
                                                                     "algorithm": "HmacSHA1"})}]})
    realm = json.loads((ROOT / "infra" / "keycloak" / "realm-aegis.template.json").read_text())
    realm["users"] = users
    _write(OUT / "realm-aegis.json", json.dumps(realm, ensure_ascii=False, indent=1))
    _write(OUT / "test-users.env", "# 시험 IdP 사용자 (local 전용, 비커밋)\n" + "".join(f"{k}={v}\n" for k, v in env.items()))
    _write(OUT / "admin.env", f"KC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(18)}\n")
    print(f"생성: {OUT.relative_to(ROOT)} — 사용자 {len(users)} (비밀번호·TOTP 비밀은 test-users.env)")


def totp(user: str, at: float | None = None) -> str:
    key = _load()[_var(user, "OTP")].encode()
    mac = hmac.new(key, struct.pack(">Q", int((at or time.time()) // 30)), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


if __name__ == "__main__":
    if sys.argv[1:2] == ["totp"]:
        print(totp(sys.argv[2]))
    else:
        generate()
