"""내부 상호 TLS (Epic 48 · NFR-D3 모든 내부 구간 상호 TLS) — prod 는 실행 시 만든 내부 CA 로 내부 구간을 상호 TLS 로 맺는다.

인증서: compose tls-init(scripts/certs.py) 가 볼륨 tls 에 만들고, 서비스는 자기 하위 경로만 /tls 에 읽기 전용으로 붙인다.
TLS_DIR 이 비면(local) 평문 — 개발 모드. 구간과 인증 방식은 SEGMENTS.
"""
from __future__ import annotations

import os
import ssl
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings

SEGMENTS = [
    {"from": "web", "to": "api", "auth": "TLS + 클라이언트 인증서 필수(uvicorn CERT_REQUIRED)"},
    {"from": "api·worker", "to": "db", "auth": "libpq verify-full + 클라이언트 인증서(pg_hba hostssl clientcert=verify-ca) + SCRAM"},
    {"from": "db-standby·db-backup", "to": "db", "auth": "복제 hostssl clientcert=verify-full(CN=replicator) + SCRAM"},
    {"from": "api·worker", "to": "otel-collector", "auth": "OTLP TLS + 클라이언트 인증서 필수(client_ca_file)"},
    {"from": "api", "to": "guard", "auth": "TLS + 클라이언트 인증서 필수(안전 분류 모델, 켠 경우)"},
]


def _dir() -> Path | None:
    return Path(settings.tls_dir) if settings.tls_dir else None


def client_context() -> ssl.SSLContext | None:
    """내부 서비스로 나가는 연결용(서버 인증서 = 내부 CA 검증 + 이 서비스의 클라이언트 인증서). local 은 None."""
    d = _dir()
    if d is None:
        return None
    ctx = ssl.create_default_context(cafile=str(d / "ca.crt"))
    ctx.load_cert_chain(str(d / "tls.crt"), str(d / "tls.key"))
    return ctx


def _cert(p: Path) -> dict:
    from cryptography import x509
    c = x509.load_pem_x509_certificate(p.read_bytes())
    return {"subject": c.subject.rfc4514_string(), "serial": format(c.serial_number, "x")[:16], "notAfter": c.not_valid_after_utc.isoformat(),
            "daysLeft": (c.not_valid_after_utc - datetime.now(UTC)).days}


def status(s) -> dict:
    d = _dir()
    out = {"enabled": d is not None, "segments": SEGMENTS}
    if d is None:
        return out | {"detail": "local 은 평문(개발 모드) — 상호 TLS 는 prod 구성"}
    out |= {"ca": _cert(d / "ca.crt"), "leaf": _cert(d / "tls.crt"),
            "otel": {"endpoint": settings.otel_endpoint, "clientCert": bool(os.environ.get("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"))}}
    if s.get_bind().dialect.name == "postgresql":
        # 지금 이 연결이 실제로 TLS 인지 — libpq 쪽 관찰. pg_stat_ssl 은 SET ROLE aegis_app 뒤 자기 행도 숨긴다(세션 사용자 ≠ 현재 역할)
        raw = s.connection().connection.dbapi_connection
        out["db"] = {"ssl": bool(raw.pgconn.ssl_in_use), "sslmode": raw.info.get_parameters().get("sslmode"),
                     "clientCert": bool(os.environ.get("PGSSLCERT"))}
    return out
