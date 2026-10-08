# aegismesh — python-fastapi (multi-stage: dev = local 모드, runtime = prod 모드)
# 고정 판(Epic 54·55·58) — 이미지에 굽는 외부 참조 데이터. `make pins-refresh` 가 다음 판을 정해 이 세 줄을 고친다(그 뒤 재빌드)
ARG DBIP_MONTH=2026-10
ARG DBIP_SHA256=c839d407f85a1e0bddba354cef16b2c398182d1c34ed8d985555dce134b36b14
ARG FIDO_MDS_SNAPSHOT=2026-10
# L2 격리(Epic 65) — gVisor 고정 판. 아키텍처별 묶음 sha256 (게시된 sha512 로 확인한 뒤 고정)
ARG GVISOR_RELEASE=20260928.0
ARG GVISOR_SHA256_X86_64=1f2a732d12072eda6b8a64eccf9829fe9f4a1893d3292a7e8005a82089811d8d
ARG GVISOR_SHA256_AARCH64=fc23acbf56a98f9e95267eec431870cff9354dca7e0620da48749f881eed85b6
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv UV_LINK_MODE=copy PATH=/opt/venv/bin:$PATH PYTHONPATH=/app
RUN pip install --no-cache-dir uv
# SPIRE CLI(Epic 53) — Workload API 로 JWT-SVID 받기(spire-agent)·등록 항목 동기화(spire-server). 고정 판 정적 바이너리
COPY --from=ghcr.io/spiffe/spire-agent:1.15.3 /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY --from=ghcr.io/spiffe/spire-server:1.15.3 /opt/spire/bin/spire-server /usr/local/bin/spire-server
WORKDIR /app

# FIDO MDS3 스냅숏(Epic 54) — 보안 키 증명 체인의 근거. 빌드 때 받고(BuildKit 캐시 7일, 받기 실패 시 캐시 사본) FIDO 서명 체인을
# GlobalSign Root CA - R3(지문 고정)·서명자 이름·CRL 로 검증한다. 검증 실패 = 빌드 실패. 매달 갱신은 FIDO_MDS_SNAPSHOT 을 바꿔 다시 빌드
FROM base AS mds
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev
ARG FIDO_MDS_SNAPSHOT
ARG FIDO_MDS_TRIES=4
# 받기 실패(요청 제한 등) 때 FIDO_MDS_OPTIONAL=1 을 명시하면 스냅숏 없이 계속 — 허용목록 테넌트 보안 키 등록은 닫힌 실패(mds_unavailable).
# 받은 스냅숏의 검증 실패는 이 값과 관계없이 빌드 실패
ARG FIDO_MDS_OPTIONAL=0
COPY scripts/fetch_mds.py /tmp/fetch_mds.py
RUN --mount=type=cache,id=aegis-fido-mds,target=/cache echo "MDS snapshot ${FIDO_MDS_SNAPSHOT}" \
 && { FIDO_MDS_SNAPSHOT=${FIDO_MDS_SNAPSHOT} FIDO_MDS_TRIES=$([ "$FIDO_MDS_OPTIONAL" = 1 ] && echo 1 || echo "$FIDO_MDS_TRIES") python /tmp/fetch_mds.py /opt/fido --cache /cache \
      || { [ "$FIDO_MDS_OPTIONAL" = 1 ] && mkdir -p /opt/fido && echo "MDS 받기 실패 — FIDO_MDS_OPTIONAL=1: 스냅숏 없이 계속"; }; }
COPY app/__init__.py app/fido.py app/
RUN if [ -f /opt/fido/blob.jwt ] || [ "$FIDO_MDS_OPTIONAL" != 1 ]; then python -m app.fido verify /opt/fido --crl; fi

# 지오 IP(Epic 55) — DB-IP IP to City Lite(CC BY 4.0, https://db-ip.com) 월간 판을 sha256 으로 고정(맨 위 전역 ARG)
FROM base AS geoip
ARG DBIP_MONTH
ARG DBIP_SHA256
ADD --checksum=sha256:${DBIP_SHA256} https://download.db-ip.com/free/dbip-city-lite-${DBIP_MONTH}.mmdb.gz /tmp/dbip.mmdb.gz
RUN mkdir -p /opt/geoip && gzip -dc /tmp/dbip.mmdb.gz > /opt/geoip/dbip-city-lite.mmdb \
 && printf '{"month":"%s","sha256":"%s","source":"https://db-ip.com","license":"CC BY 4.0"}' "$DBIP_MONTH" "$DBIP_SHA256" > /opt/geoip/meta.json

# 고정 판 다음 판 정하기(Epic 58) — `make pins-refresh` 만 쓴다. 네트워크는 이 빌드 안에서만, 결과 JSON 은 pins-out 으로 내보낸다
FROM base AS pins
ARG DBIP_MONTH
ARG DBIP_SHA256
ARG FIDO_MDS_SNAPSHOT
ARG PINS_AT=0
COPY --from=mds /opt/fido /opt/fido
COPY scripts/pins.py /tmp/pins.py
RUN echo "pins ${PINS_AT}" && DBIP_MONTH=${DBIP_MONTH} DBIP_SHA256=${DBIP_SHA256} FIDO_MDS_SNAPSHOT=${FIDO_MDS_SNAPSHOT} python /tmp/pins.py resolve /pins.json

FROM scratch AS pins-out
COPY --from=pins /pins.json /pins.json

# dev: 테스트/개발 의존성 포함, 소스는 local 모드에서 바인드 마운트
FROM base AS dev
COPY --from=mds /opt/fido /opt/fido
COPY --from=geoip /opt/geoip /opt/geoip
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# runtime: 운영 의존성만
FROM base AS runtime
COPY --from=mds /opt/fido /opt/fido
COPY --from=geoip /opt/geoip /opt/geoip
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev
COPY . .
RUN useradd -r -u 10001 app && mkdir -p /app/data && chown -R app /app/data
USER app
EXPOSE 8000
# 작업 프로세스 수 = WEB_CONCURRENCY (uvicorn 기본 규약, 기본 2 — .env.prod 로 조정)
ENV WEB_CONCURRENCY=2
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# gvisor: runsc 고정 판 받기·검증(불일치 = 빌드 실패)
FROM debian:trixie-slim AS gvisor
ARG GVISOR_RELEASE
ARG GVISOR_SHA256_X86_64
ARG GVISOR_SHA256_AARCH64
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates zstd && rm -rf /var/lib/apt/lists/*
RUN set -e; A=$(uname -m); case "$A" in x86_64) S=$GVISOR_SHA256_X86_64 ;; aarch64) S=$GVISOR_SHA256_AARCH64 ;; *) exit 1 ;; esac; \
    curl -fsSL -o /tmp/g.tar.zstd "https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/$A/gvisor.tar.zstd"; \
    echo "$S  /tmp/g.tar.zstd" | sha256sum -c; mkdir /opt/gvisor; tar --zstd -xf /tmp/g.tar.zstd -C /opt/gvisor; rm /tmp/g.tar.zstd; \
    /opt/gvisor/runsc --version

# l2: L2 격리 브로커(Epic 65, compose sandbox-l2) — runsc + 샌드박스 루트 FS(= runtime 이미지 사본, 비밀 없음) + 브로커(표준 라이브러리)
#   샌드박스는 이 루트 FS 를 읽기 전용 + 1회용 tmpfs 덧씌움으로 본다. 브로커의 /tls·/registry 는 루트 FS 밖이라 보이지 않는다
FROM python:3.12-slim AS l2
COPY --from=gvisor /opt/gvisor/runsc /usr/local/bin/runsc
COPY --from=gvisor /opt/gvisor/gvisor-bin /usr/local/bin/gvisor-bin
COPY --from=runtime / /sandbox-rootfs
COPY infra/gvisor/broker.py /opt/l2/broker.py
RUN useradd -r -u 10001 app && mkdir /sandbox-rootfs/agent       # 번들 붙일 자리(루트 FS 는 읽기 전용)
USER app
EXPOSE 8080
CMD ["python", "/opt/l2/broker.py"]

# cli: 단일 파일 aegis (PyInstaller onefile, 이 이미지의 OS·아키텍처용 — 리눅스)
#   make cli  →  dist/aegis-linux-<arch>
# glibc 호환 범위를 넓히려고 bookworm(glibc 2.36)에서 빌드 — 실행 호스트는 glibc ≥ 2.36
FROM python:3.12-slim-bookworm AS cli-build
ENV PYTHONDONTWRITEBYTECODE=1 UV_PROJECT_ENVIRONMENT=/opt/venv UV_LINK_MODE=copy PATH=/opt/venv/bin:$PATH PYTHONPATH=/app
RUN pip install --no-cache-dir uv && apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev && uv pip install "pyinstaller>=6.10"
COPY aegis ./aegis
COPY agents ./agents
COPY scripts ./scripts
COPY diagram_items.json ./
RUN python scripts/build_cli.py && ./dist/aegis list | head -3

FROM scratch AS cli
COPY --from=cli-build /app/dist/aegis /aegis
