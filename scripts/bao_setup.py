"""OpenBao 시크릿 백엔드 시험 구성 (Epic 41, compose 프로파일 bao · local 전용) — 비밀은 실행 때 만들고 커밋하지 않는다.

  python scripts/bao_setup.py keys        # infra/openbao/bao.env (dev 서버 루트 토큰, 있으면 유지)
  python scripts/bao_setup.py configure   # 정책 aegis-broker·aegis-lease-holder, 토큰 역할 aegis-lease, 브로커 토큰 → infra/openbao/api.env
  운영형(Epic 46, OPENBAO_SETUP_ADDR=http://bao-server:8200):
  python scripts/bao_setup.py init        # 초기화(키 3개·임계 2, infra/openbao/init.json 비커밋) → 봉인 해제 → 감사 장치 → configure
  python scripts/bao_setup.py unseal      # 재기동 뒤 봉인 해제(init.json 의 키 2개)
  python scripts/bao_setup.py rotate-kek  # 저장 암호화 KEK(transit aegis-kek) 새 버전 — 옛 버전은 복호화 전용으로 남는다(Epic 49)
  운영 마감 클러스터(Epic 56, prod 리허설 · 상호 TLS = BAO_CACERT·BAO_CLIENT_CERT·BAO_CLIENT_KEY):
  python scripts/bao_setup.py unsealer        # 봉인 해제기 초기화(Shamir 3/2, unsealer-init.json)·봉인 해제·transit aegis-autounseal·포장 전용 토큰 → cluster.env
  python scripts/bao_setup.py cluster-init    # bao-1 초기화(복구 키 3/2, cluster-init.json) → 자동 봉인 해제 → 3노드 투표자 확인 → configure → cluster-api.env
  python scripts/bao_setup.py cluster-status  # 노드별 봉인·리더·raft 투표자·자동 봉인 해제 방식
  HSM 봉인 리허설(Epic 68, prod · bao-hsm):
  python scripts/bao_setup.py hsm-init        # 초기화(복구 키 3/2, hsm-init.json 비커밋) → PKCS#11 자동 봉인 해제 확인 → 점검 비밀 쓰기·읽기
  python scripts/bao_setup.py hsm-status      # 봉인 방식·상태 + 점검 비밀 읽기(재기동 뒤 데이터 확인)

루트 토큰은 이 구성에만 쓴다. api 는 브로커 토큰(역할로 임대 토큰 만들기 + accessor 조회·갱신·회수만)으로 동작한다.
dev 서버는 메모리 저장이라 bao 가 재기동되면 `make bao-up` 으로 다시 구성한다.
"""
from __future__ import annotations

import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "infra" / "openbao"
ADDR = os.environ.get("OPENBAO_SETUP_ADDR", "http://bao:8200")
MAX_SEC = int(os.environ.get("SECRET_LEASE_MAX_SEC", "900"))

BROKER = """
path "auth/token/create/aegis-lease" { capabilities = ["create", "update"] }
path "auth/token/lookup-accessor"    { capabilities = ["update"] }
path "auth/token/renew-accessor"     { capabilities = ["update"] }
path "auth/token/revoke-accessor"    { capabilities = ["update"] }
path "transit/encrypt/aegis-kek"     { capabilities = ["update"] }
path "transit/decrypt/aegis-kek"     { capabilities = ["update"] }
"""
KEK = "aegis-kek"                        # 저장 암호화 KEK (Epic 49, KMS_BACKEND=openbao) — 브로커는 포장·해제만, 회전은 이 스크립트(루트)
HOLDER = 'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
UNSEALER = os.environ.get("OPENBAO_UNSEALER_ADDR", "https://bao-unsealer:8200")
NODES = ["https://bao-1:8200", "https://bao-2:8200", "https://bao-3:8200"]
HSM = os.environ.get("OPENBAO_HSM_ADDR", "https://bao-hsm:8200")
AUTOUNSEAL_KEY = "aegis-autounseal"
AUTOUNSEAL = (f'path "transit/encrypt/{AUTOUNSEAL_KEY}" {{ capabilities = ["update"] }}\n'
              f'path "transit/decrypt/{AUTOUNSEAL_KEY}" {{ capabilities = ["update"] }}\n')


def _write(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o600)


def _env(path: Path) -> dict[str, str]:
    return dict(x.split("=", 1) for x in path.read_text().splitlines() if "=" in x and not x.startswith("#")) if path.exists() else {}


def _tls() -> ssl.SSLContext | None:
    if not os.environ.get("BAO_CACERT"):
        return None
    c = ssl.create_default_context(cafile=os.environ["BAO_CACERT"])
    c.load_cert_chain(os.environ["BAO_CLIENT_CERT"], os.environ["BAO_CLIENT_KEY"])
    return c


def call(method: str, path: str, token: str | None, body: dict | None = None, timeout: int = 10, addr: str | None = None) -> dict:
    a = addr or ADDR
    req = urllib.request.Request(f"{a}/v1/{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json"} | ({"X-Vault-Token": token} if token else {}))
    with urllib.request.urlopen(req, timeout=timeout, context=_tls() if a.startswith("https") else None) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def keys() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    f = OUT / "bao.env"
    if "BAO_DEV_ROOT_TOKEN_ID" not in _env(f):
        _write(f, "# OpenBao dev 서버 루트 토큰 (local 시험 전용, 비커밋)\nBAO_DEV_ROOT_TOKEN_ID=" + secrets.token_urlsafe(24) + "\n")
    print(f"keys ok → {f.relative_to(ROOT)}")


SERVER = "bao-server" in ADDR


def _root() -> str:
    """운영형은 init.json 의 루트 토큰(구성에만), dev 는 bao.env."""
    if SERVER:
        return json.loads((OUT / "init.json").read_text())["root_token"]
    return _env(OUT / "bao.env")["BAO_DEV_ROOT_TOKEN_ID"]


def _status(addr: str | None = None) -> dict:
    for _ in range(60):
        try:
            return call("GET", "sys/seal-status", None, addr=addr)
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    raise SystemExit(f"OpenBao 응답 없음 — {addr or ADDR}")


def unseal() -> None:
    st = _status()
    if st.get("sealed"):
        keys = json.loads((OUT / "init.json").read_text())["keys_b64"]
        for k in keys[: st["t"]]:
            st = call("PUT", "sys/unseal", None, {"key": k})
    print(f"unseal — sealed {st['sealed']} · 임계 {st['t']}/{st['n']} · {st.get('version')}")


def init() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    st = _status()
    if not st.get("initialized"):
        r = call("PUT", "sys/init", None, {"secret_shares": 3, "secret_threshold": 2}, timeout=120)   # raft 부트스트랩이 느리다 — 응답을 놓치면 키를 잃는다
        _write(OUT / "init.json", json.dumps({"keys_b64": r["keys_base64"], "root_token": r["root_token"]}))
        print("init — 키 3개·임계 2 → infra/openbao/init.json (비커밋, 운영은 키 보관자 분리·자동 봉인 해제)")
    unseal()
    root = _root()
    for _ in range(60):                                                 # 봉인 해제 직후 raft 리더 선출 대기(그전엔 500/429)
        try:
            if call("GET", "sys/leader", None).get("is_self"):
                break
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    audits = call("GET", "sys/audit", root)
    found = audits.get("data") or audits
    print("audit — " + (f"선언된 장치 {sorted(k for k in found if k.endswith('/'))} (infra/openbao/config.hcl, 토큰·비밀은 HMAC)" if found
                        else "감사 장치 없음 — config.hcl 의 audit 블록 확인"))
    configure()


def configure(root: str | None = None, env_name: str = "api.env", env_extra: str = "") -> None:
    root = root or _root()
    for _ in range(30):                                                 # 준비 대기(봉인 해제 상태)
        try:
            if not call("GET", "sys/health?standbyok=true", root).get("sealed", True):
                break
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    if "transit/" not in call("GET", "sys/mounts", root).get("data", {}):           # 저장 암호화 KMS(Epic 49)
        call("POST", "sys/mounts/transit", root, {"type": "transit"})
    try:
        call("GET", f"transit/keys/{KEK}", root)
    except urllib.error.HTTPError:
        call("POST", f"transit/keys/{KEK}", root, {"type": "aes256-gcm96"})
    call("PUT", "sys/policies/acl/aegis-broker", root, {"policy": BROKER})
    call("PUT", "sys/policies/acl/aegis-lease-holder", root, {"policy": HOLDER})
    call("POST", "auth/token/roles/aegis-lease", root, {
        "allowed_policies": ["aegis-lease-holder"], "disallowed_policies": ["root", "aegis-broker"], "orphan": True,
        "renewable": True, "token_type": "service", "token_explicit_max_ttl": f"{MAX_SEC}s", "token_no_default_policy": True})
    broker = call("POST", "auth/token/create-orphan", root, {"policies": ["aegis-broker"], "period": "24h", "display_name": "aegis-broker",
                                                             "no_default_policy": False})["auth"]["client_token"]
    _write(OUT / env_name, "# OpenBao 임대 백엔드 (make bao-up·bao-cluster-up 이 생성, 비커밋) — 지우면 내장 브로커로 돌아간다\n"
           f"SECRETS_BACKEND=openbao\nOPENBAO_ADDR={env_extra and ','.join(NODES) or ADDR}\nOPENBAO_TOKEN={broker}\n{env_extra}")
    v = call("GET", "sys/health?standbyok=true", root).get("version")
    print(f"configure ok — OpenBao {v} · role aegis-lease (explicit max {MAX_SEC}s) · transit {KEK} · broker token → infra/openbao/{env_name}")


def rotate_kek() -> None:
    root = _root()
    call("POST", f"transit/keys/{KEK}/rotate", root, {})
    k = call("GET", f"transit/keys/{KEK}", root)["data"]
    print(f"rotate-kek — {KEK} 최신 v{k['latest_version']} · 복호화 최소 v{k['min_decryption_version']} (옛 버전은 복호화 전용)")


def _unseal_shamir(addr: str, init_file: Path) -> dict:
    st = _status(addr)
    if st.get("sealed"):
        for k in json.loads(init_file.read_text())["keys_b64"][: st["t"]]:
            st = call("PUT", "sys/unseal", None, {"key": k}, addr=addr)
    return st


def _wait_leader(addr: str) -> None:
    for _ in range(60):                                                 # 봉인 해제 직후 raft 리더 선출 대기
        try:
            if call("GET", "sys/leader", None, addr=addr).get("leader_address"):
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    raise SystemExit(f"리더 없음 — {addr}")


def unsealer() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    f = OUT / "unsealer-init.json"
    if not _status(UNSEALER).get("initialized"):
        r = call("PUT", "sys/init", None, {"secret_shares": 3, "secret_threshold": 2}, timeout=120, addr=UNSEALER)
        _write(f, json.dumps({"keys_b64": r["keys_base64"], "root_token": r["root_token"]}))
        print("unsealer init — Shamir 키 3개·임계 2 → infra/openbao/unsealer-init.json (비커밋, 운영은 키 보관자 분리)")
    st = _unseal_shamir(UNSEALER, f)
    _wait_leader(UNSEALER)
    root = json.loads(f.read_text())["root_token"]
    if "transit/" not in call("GET", "sys/mounts", root, addr=UNSEALER).get("data", {}):
        call("POST", "sys/mounts/transit", root, {"type": "transit"}, addr=UNSEALER)
    try:
        call("GET", f"transit/keys/{AUTOUNSEAL_KEY}", root, addr=UNSEALER)
    except urllib.error.HTTPError:
        call("POST", f"transit/keys/{AUTOUNSEAL_KEY}", root, {"type": "aes256-gcm96"}, addr=UNSEALER)
    call("PUT", f"sys/policies/acl/{AUTOUNSEAL_KEY}", root, {"policy": AUTOUNSEAL}, addr=UNSEALER)
    env = OUT / "cluster.env"
    tok = _env(env).get("BAO_TOKEN")
    try:
        ok = bool(tok) and AUTOUNSEAL_KEY in call("GET", "auth/token/lookup-self", tok, addr=UNSEALER)["data"]["policies"]
    except urllib.error.HTTPError:
        ok = False
    if not ok:                                                          # 주기 토큰 — transit 봉인이 스스로 갱신한다
        tok = call("POST", "auth/token/create-orphan", root, {"policies": [AUTOUNSEAL_KEY], "period": "24h", "no_default_policy": True,
                                                              "display_name": "aegis-autounseal"}, addr=UNSEALER)["auth"]["client_token"]
        _write(env, "# 3노드 자동 봉인 해제 토큰(봉인 해제기 transit aegis-autounseal 포장·해제 전용, make bao-cluster-up 이 생성, 비커밋)\n"
               f"BAO_TOKEN={tok}\n")
    print(f"unsealer ok — sealed {st['sealed']} · {st.get('version')} · transit {AUTOUNSEAL_KEY} · 포장 전용 토큰 → infra/openbao/cluster.env")


def _raft(root: str) -> list[dict]:
    for a in NODES:
        try:
            return call("GET", "sys/storage/raft/configuration", root, addr=a)["data"]["config"]["servers"]
        except (urllib.error.URLError, OSError, KeyError):
            continue
    return []


def cluster_init() -> None:
    f = OUT / "cluster-init.json"
    t0 = time.time()
    if not _status(NODES[0]).get("initialized"):
        r = call("PUT", "sys/init", None, {"recovery_shares": 3, "recovery_threshold": 2}, timeout=120, addr=NODES[0])
        _write(f, json.dumps({"recovery_keys_b64": r["recovery_keys_base64"], "root_token": r["root_token"]}))
        print("cluster init — 자동 봉인 해제(transit) · 복구 키 3개·임계 2 → infra/openbao/cluster-init.json (비커밋)")
    root = json.loads(f.read_text())["root_token"]
    for _ in range(180):                                                # bao-2·3 retry_join → 자동 봉인 해제 → 자동 조종이 투표자로 승격
        servers = _raft(root)
        sealed = [a for a in NODES if _status(a).get("sealed")]
        if len(servers) == 3 and all(s.get("voter") for s in servers) and not sealed:
            break
        time.sleep(1)
    else:
        raise SystemExit(f"클러스터 미완성 — servers {[(s['node_id'], s.get('voter')) for s in _raft(root)]} · 봉인 {sealed}")
    print(f"raft — 투표자 {len(servers)} · 리더 {next(s['node_id'] for s in servers if s.get('leader'))} · {time.time() - t0:.0f}s")
    global ADDR
    ADDR = NODES[0]
    configure(root, "cluster-api.env", "OPENBAO_CA_FILE=/tls/ca.crt\nOPENBAO_CLIENT_CERT=/tls/tls.crt\nOPENBAO_CLIENT_KEY=/tls/tls.key\n")


def cluster_status() -> None:
    root = json.loads((OUT / "cluster-init.json").read_text())["root_token"] if (OUT / "cluster-init.json").exists() else None
    for a in [UNSEALER, *NODES]:
        try:
            st = call("GET", "sys/seal-status", None, addr=a, timeout=3)
            ld = call("GET", "sys/leader", None, addr=a, timeout=3) if not st.get("sealed") else {}
            print(f"{a.split('//')[1]:<20} sealed={st['sealed']!s:<5} type={st.get('type'):<8} recovery={st.get('recovery_seal')!s:<5} "
                  f"leader={ld.get('is_self')!s:<5} {st.get('version')}")
        except (urllib.error.URLError, OSError) as e:
            print(f"{a.split('//')[1]:<20} 응답 없음 — {e}")
    if root:
        print("raft —", ", ".join(f"{s['node_id']}{'*' if s.get('leader') else ''}{'' if s.get('voter') else '(non-voter)'}" for s in _raft(root)))


def hsm_init() -> None:
    f = OUT / "hsm-init.json"
    t0 = time.time()
    st = _status(HSM)
    if not st.get("initialized"):
        r = call("PUT", "sys/init", None, {"recovery_shares": 3, "recovery_threshold": 2}, timeout=120, addr=HSM)
        _write(f, json.dumps({"recovery_keys_b64": r["recovery_keys_base64"], "root_token": r["root_token"]}))
        print("hsm init — PKCS#11 자동 봉인 해제 · 복구 키 3개·임계 2 → infra/openbao/hsm-init.json (비커밋)")
    for _ in range(60):
        st = _status(HSM)
        if not st.get("sealed"):
            break
        time.sleep(1)
    else:
        raise SystemExit(f"봉인 해제 안 됨 — {st}")
    root = json.loads(f.read_text())["root_token"]
    try:
        call("POST", "sys/mounts/aegis-hsm", root, {"type": "kv", "options": {"version": "2"}}, addr=HSM)
    except urllib.error.HTTPError as e:
        if e.code != 400:                                                # 이미 있음
            raise
    for _ in range(30):
        try:
            call("POST", "aegis-hsm/data/probe", root, {"data": {"marker": secrets.token_hex(8), "at": int(time.time())}}, addr=HSM)
            break
        except urllib.error.HTTPError:
            time.sleep(1)
    print(f"hsm — sealed {st['sealed']} · type {st.get('type')} · recovery_seal {st.get('recovery_seal')} · {st.get('version')} · {time.time() - t0:.1f}s")
    hsm_status()


def hsm_status() -> None:
    st = call("GET", "sys/seal-status", None, addr=HSM, timeout=5)
    line = f"bao-hsm sealed={st['sealed']} type={st.get('type')} recovery_seal={st.get('recovery_seal')} initialized={st.get('initialized')} {st.get('version')}"
    f = OUT / "hsm-init.json"
    if not st["sealed"] and f.exists():
        d = call("GET", "aegis-hsm/data/probe", json.loads(f.read_text())["root_token"], addr=HSM)["data"]
        line += f" · 점검 비밀 v{d['metadata']['version']} marker={d['data']['marker'][:4]}…"
    print(line)


if __name__ == "__main__":
    {"hsm-init": hsm_init, "hsm-status": hsm_status, "keys": keys, "configure": configure, "init": init, "unseal": unseal, "rotate-kek": rotate_kek, "unsealer": unsealer,
     "cluster-init": cluster_init, "cluster-status": cluster_status}[sys.argv[1] if len(sys.argv) > 1 else "keys"]()
