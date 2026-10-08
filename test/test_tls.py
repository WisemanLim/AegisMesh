"""Epic 48 — 내부 상호 TLS (NFR-D3): 내부 CA·말단 인증서 발급·갱신·회전, 상호 인증 핸드셰이크, 상태 API, prod 구성 고정.

실제 구간(web→api·api→db·복제·OTLP)의 평문 거부·회전 무중단은 prod 리허설(make prod-all · make certs-rotate ENV=prod)에서 확인한다.
"""
import os
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from app import tls
from app.core.config import settings

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import certs


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setattr(certs, "ROOT", tmp_path / "tls")
    monkeypatch.setattr(certs, "OUT", tmp_path / "out")
    assert certs.main(["ensure"]) == 0
    return tmp_path / "tls"


def _load(p):
    return x509.load_pem_x509_certificate(p.read_bytes())


def test_ensure_issues_ca_and_leaves_with_owners_and_usage(tree):
    ca = _load(tree / "ca" / "ca.crt")
    assert oct((tree / "ca" / "ca.key").stat().st_mode & 0o777) == "0o600"
    for name, (cn, dns, usage, uid) in certs.LEAVES.items():
        d = tree / name
        c = _load(d / "tls.crt")
        c.verify_directly_issued_by(ca)                                                 # 내부 CA 서명
        assert c.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == cn
        assert list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == usage
        assert (d / "tls.key").stat().st_uid == uid and oct((d / "tls.key").stat().st_mode & 0o777) == "0o600"
        if dns:
            assert set(dns) <= set(c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    db_san = _load(tree / "db" / "tls.crt").extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {"db", "db-standby", "db-drill"} <= set(db_san.get_values_for_type(x509.DNSName))   # 승격·복구 훈련 서버도 같은 인증서
    rep = _load(tree / "replicator" / "tls.crt")
    assert ExtendedKeyUsageOID.SERVER_AUTH not in rep.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value


def test_ensure_renews_leaves_near_expiry(tree, monkeypatch):
    before = _load(tree / "db" / "tls.crt").serial_number
    monkeypatch.setattr(certs, "RENEW_DAYS", 95)                                       # 90일 말단 = 갱신 구간 안
    certs.main(["ensure"])
    assert _load(tree / "db" / "tls.crt").serial_number != before


def test_ensure_keeps_rotate_reissues_with_same_ca(tree, capsys):
    before = _load(tree / "api" / "tls.crt").serial_number
    certs.main(["ensure"])
    assert "api: 유지" in capsys.readouterr().out and _load(tree / "api" / "tls.crt").serial_number == before
    ca_before = (tree / "ca" / "ca.crt").read_bytes()
    certs.main(["rotate"])
    after = _load(tree / "api" / "tls.crt")
    assert after.serial_number != before and (tree / "ca" / "ca.crt").read_bytes() == ca_before
    after.verify_directly_issued_by(_load(tree / "ca" / "ca.crt"))


def test_client_bundle_for_external_tools(tree, tmp_path):
    assert certs.main(["client", "operator"]) == 0
    c = _load(tmp_path / "out" / "operator" / "tls.crt")
    assert list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert certs.main(["client", "../evil"]) == 2                                      # 경로 이탈 이름 거부


def _server(tree, require_client: bool):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(tree / "api" / "ca.crt"))
    ctx.load_cert_chain(str(tree / "api" / "tls.crt"), str(tree / "api" / "tls.key"))
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_NONE
    srv = socket.create_server(("127.0.0.1", 0))
    seen = {}

    def serve():
        conn, _ = srv.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                seen["peer"] = s.getpeercert()
                s.sendall(b"ok")
        except (ssl.SSLError, OSError) as e:
            seen["error"] = type(e).__name__

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], seen


def test_mutual_handshake_uses_internal_ca_and_client_cert(tree, monkeypatch):
    monkeypatch.setattr(settings, "tls_dir", str(tree / "web"))                        # 콘솔(web) 인증서로 api 에 접속
    port, seen = _server(tree, require_client=True)
    with socket.create_connection(("127.0.0.1", port)) as raw, tls.client_context().wrap_socket(raw, server_hostname="localhost") as s:
        assert s.recv(2) == b"ok"
    assert dict(x[0] for x in seen["peer"]["subject"])["commonName"] == "web"          # 서버가 본 클라이언트 신원
    port, seen = _server(tree, require_client=True)
    bare = ssl.create_default_context(cafile=str(tree / "web" / "ca.crt"))              # 클라이언트 인증서 없음 → 거부
    with (socket.create_connection(("127.0.0.1", port)) as raw, pytest.raises((ssl.SSLError, ConnectionResetError, OSError)),
          bare.wrap_socket(raw, server_hostname="localhost") as s):
        s.recv(2)
    port, _ = _server(tree, require_client=False)
    with socket.create_connection(("127.0.0.1", port)) as raw, pytest.raises(ssl.SSLCertVerificationError):
        tls.client_context().wrap_socket(raw, server_hostname="api.evil")              # 서버 이름 불일치 → 클라이언트가 거부


def test_status_api(client, tree, monkeypatch):
    d = client.get("/v1/observability/tls").json()
    assert d["enabled"] is False and len(d["segments"]) == 5                            # local = 평문 개발 모드
    monkeypatch.setattr(settings, "tls_dir", str(tree / "api"))
    d = client.get("/v1/observability/tls").json()
    assert d["enabled"] and 85 <= d["leaf"]["daysLeft"] <= 90 and d["ca"]["subject"].endswith("O=AegisMesh")


def test_prod_compose_requires_tls_on_every_internal_segment():
    c = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())["services"]
    assert c["api"]["command"][-2:] == ["--ssl-cert-reqs", "2"]                          # 클라이언트 인증서 필수
    assert c["web"]["environment"]["API_URL"].startswith("https://")
    for s in ("api", "worker"):
        assert c[s]["environment"]["PGSSLMODE"] == "verify-full"
    for s in ("db-standby", "db-backup"):
        assert c[s]["environment"]["PGSSLMODE"] == "verify-full" and c[s]["environment"]["PGSSLCERT"].startswith("/tls/client/")
    assert "ssl=on" in c["db"]["command"]
    assert all(c[s]["depends_on"]["tls-init"]["condition"] == "service_completed_successfully" for s in ("api", "worker", "web", "db", "otel-collector"))
    hosts = [x.split() for x in (ROOT / "infra/postgres/pg_hba.conf").read_text().splitlines() if x.startswith("host")]
    remote = [x for x in hosts if x[3] not in ("127.0.0.1/32", "::1/128")]
    assert remote and all(x[0] == "hostssl" and x[-1].startswith("clientcert=") for x in remote)   # 평문 원격 줄 없음
    assert ["hostssl", "replication", "replicator", "all", "scram-sha-256", "clientcert=verify-full"] in hosts
    otel = yaml.safe_load((ROOT / "infra/otel/tls.yaml").read_text())["receivers"]["otlp"]["protocols"]
    assert all(otel[p]["tls"]["client_ca_file"] == "/tls/ca.crt" for p in ("http", "grpc"))
    assert "infra/tls/" in (ROOT / ".gitignore").read_text() and os.environ.get("TLS_DIR", "") == ""
