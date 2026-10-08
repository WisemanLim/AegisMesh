# 외부 레드팀 엔진 garak (Epic 59 · NVIDIA, Apache-2.0) — 고정 판을 이미지 빌드 때만 받는다. 실행 중 모델·데이터 내려받기 없음.
# AegisMesh 관문을 거친 대상(garak-target)과 무방비 대상(되풀이 모델)에 같은 탐침을 돌려 공격 성공률을 비교한다(make garak-scan).
ARG GARAK_VERSION=0.13.1

# 휠 빌더 — garak 의존성 base2048 은 aarch64 휠이 없어 Rust 로 빌드한다(고정 판 Rust 툴체인, 결과 휠만 넘긴다)
FROM python:3.12-slim AS wheels
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY --from=rust:1.89-slim-trixie /usr/local/cargo /usr/local/cargo
COPY --from=rust:1.89-slim-trixie /usr/local/rustup /usr/local/rustup
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels base2048==0.1.3

FROM python:3.12-slim
ARG GARAK_VERSION
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 XDG_DATA_HOME=/work XDG_CONFIG_HOME=/work/config XDG_CACHE_HOME=/work/cache
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.8.0
COPY --from=wheels /wheels /wheels
RUN pip install --no-cache-dir --find-links /wheels "garak==${GARAK_VERSION}" && garak --version
RUN useradd -r -u 10001 -m app && mkdir -p /work /out && chown -R app /work /out   # 빌드 때 garak --version 이 만든 /work/garak 까지
USER app
WORKDIR /work
ENTRYPOINT ["garak"]
