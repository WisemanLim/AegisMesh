"""내부 CA·인증서 (Epic 48 · NFR-D3 모든 내부 구간 상호 TLS) — prod compose 의 tls-init 이 실행한다(볼륨 tls, 비커밋).

  python scripts/certs.py ensure        # 없으면 만들고, 만료 30일 전이면 재발급(CA 유지). prod-all 마다 실행된다
  python scripts/certs.py rotate        # 모든 말단 인증서 즉시 재발급(CA 유지) — make certs-rotate ENV=prod
  python scripts/certs.py client NAME   # 외부 도구용 클라이언트 묶음 → /out/NAME (호스트 infra/tls/clients/NAME, 비커밋)

볼륨 배치: /tls/ca(루트 전용, CA 개인키) · /tls/<서비스>/{ca.crt,tls.crt,tls.key}. 서비스는 자기 하위 경로만 읽기 전용으로 붙인다.
키 파일은 그 서비스 실행 사용자 소유 0600(PostgreSQL 은 소유자·권한을 검사한다). 키는 ECDSA P-256, CA 5년·말단 90일.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(os.environ.get("TLS_ROOT", "/tls"))
OUT = Path(os.environ.get("TLS_OUT", "/out"))
PG, APP, BAO = 70, 10001, 100            # postgres:17-alpine · api·web·otel-collector · openbao 이미지의 실행 사용자
SERVER, CLIENT = ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH
# 서비스 → (CN, DNS SAN, 사용 용도, 소유 uid). db 인증서는 주·대기·복구 훈련 서버가 함께 쓴다(승격되면 그대로 서버가 된다).
LEAVES = {
    "db": ("db", ["db", "db-standby", "db-drill", "localhost"], [SERVER], PG),
    "replicator": ("replicator", [], [CLIENT], PG),           # 대기 서버·기본 백업 → 주 서버 (pg_hba verify-full: CN = 역할 이름)
    "api": ("api", ["api", "localhost"], [SERVER, CLIENT], APP),   # uvicorn 서버 + PG·OTel 클라이언트 (worker 도 같은 인증서)
    "web": ("web", [], [CLIENT], APP),                       # 콘솔 서버 → api
    "otel": ("otel-collector", ["otel-collector"], [SERVER], APP),
    "guard": ("guard", ["guard"], [SERVER, CLIENT], APP),        # 안전 분류 모델 서버(Epic 50) — 헬스 검사가 자기 인증서로 접속
    "objstore": ("objstore", ["objstore", "localhost"], [SERVER, CLIENT], 0),   # 외부 복사 객체 저장(Epic 52) — S3·내부 gRPC 서버이자 클라이언트, root 실행
    "nats": ("nats", ["nats"], [SERVER], 0),                      # 발견 버스(Epic 60) — root 실행 NATS
    "injguard": ("injguard", ["injguard"], [SERVER, CLIENT], APP),   # 인라인 주입 분류 모델(Epic 64) — 헬스 검사가 자기 인증서로 접속
    "sandbox-l2": ("sandbox-l2", ["sandbox-l2"], [SERVER, CLIENT], APP),   # L2 격리 브로커(Epic 65) — 비루트·능력 없음, 헬스 검사가 자기 인증서로
    "bao-unsealer": ("bao-unsealer", ["bao-unsealer"], [SERVER, CLIENT], BAO),    # OpenBao 봉인 해제기(Epic 56)
    "bao-hsm": ("bao-hsm", ["bao-hsm"], [SERVER, CLIENT], BAO),   # OpenBao HSM 봉인 리허설(Epic 68)
    "bao-1": ("bao-1", ["bao-1"], [SERVER, CLIENT], BAO),         # OpenBao raft 노드 — API·클러스터 서버 + retry_join·transit 봉인 클라이언트
    "bao-2": ("bao-2", ["bao-2"], [SERVER, CLIENT], BAO),
    "bao-3": ("bao-3", ["bao-3"], [SERVER, CLIENT], BAO),
}
CA_DAYS, LEAF_DAYS, RENEW_DAYS = 5 * 365, 90, 30


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _write(path: Path, data: bytes, uid: int, mode: int) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chown(tmp, uid, uid)
    os.chmod(tmp, mode)
    tmp.replace(path)                     # 원자 교체 — 읽는 쪽이 반쯤 쓴 파일을 보지 않는다


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    d = ROOT / "ca"
    if (d / "ca.key").exists():
        return (x509.load_pem_x509_certificate((d / "ca.crt").read_bytes()),
                serialization.load_pem_private_key((d / "ca.key").read_bytes(), None))
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisMesh"), x509.NameAttribute(NameOID.COMMON_NAME, "AegisMesh internal CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(_now() - dt.timedelta(minutes=5))
            .not_valid_after(_now() + dt.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write(d / "ca.key", _key_pem(key), 0, 0o600)
    _write(d / "ca.crt", _pem(cert), 0, 0o644)
    print(f"CA 생성 — {cert.subject.rfc4514_string()} · {cert.not_valid_after_utc:%Y-%m-%d} 까지")
    return cert, key


def issue(cn: str, dns: list[str], usage: list, ca_cert: x509.Certificate, ca_key) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisMesh"),
                                                           x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_now() - dt.timedelta(minutes=5)).not_valid_after(_now() + dt.timedelta(days=LEAF_DAYS))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False, data_encipherment=False,
                                      key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False,
                                      decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage(usage), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if dns:
        sans = [x509.DNSName(n) for n in dns] + ([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if "localhost" in dns else [])
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return _pem(b.sign(ca_key, hashes.SHA256())), _key_pem(key)


def _leaf(name: str, force: bool, ca_cert, ca_key) -> str:
    cn, dns, usage, uid = LEAVES[name]
    d = ROOT / name
    crt = d / "tls.crt"
    if crt.exists() and not force:
        left = x509.load_pem_x509_certificate(crt.read_bytes()).not_valid_after_utc - _now()
        if left > dt.timedelta(days=RENEW_DAYS) and (d / "ca.crt").read_bytes() == _pem(ca_cert):
            return f"{name}: 유지 ({left.days}일 남음)"
    d.mkdir(parents=True, exist_ok=True)
    os.chown(d, uid, uid)
    os.chmod(d, 0o700)
    cert, key = issue(cn, dns, usage, ca_cert, ca_key)
    _write(d / "ca.crt", _pem(ca_cert), uid, 0o644)
    _write(d / "tls.key", key, uid, 0o600)            # 키 먼저 — 인증서만 바뀐 순간이 없게
    _write(d / "tls.crt", cert, uid, 0o644)
    return f"{name}: 발급 CN={cn} SAN={dns or '-'} · {LEAF_DAYS}일"


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "ensure"
    ca_cert, ca_key = ca()
    if cmd in ("ensure", "rotate"):
        for name in LEAVES:
            print(_leaf(name, cmd == "rotate", ca_cert, ca_key))
        return 0
    if cmd == "client" and len(argv) == 2 and argv[1].replace("-", "").isalnum():
        d = OUT / argv[1]
        d.mkdir(parents=True, exist_ok=True)
        cert, key = issue(argv[1], [], [CLIENT], ca_cert, ca_key)
        uid = int(os.environ.get("HOST_UID", "0"))
        _write(d / "ca.crt", _pem(ca_cert), uid, 0o644)
        _write(d / "tls.key", key, uid, 0o600)
        _write(d / "tls.crt", cert, uid, 0o644)
        print(f"클라이언트 묶음 {argv[1]} → infra/tls/clients/{argv[1]}/ (비커밋, {LEAF_DAYS}일)")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
