# 안전 분류 모델 서버 (Epic 50 · OQ9 · NFR-Q2) — Qwen3Guard-Gen-0.6B (Apache-2.0, 비게이트) 고정 판을 이미지 빌드 때 받는다.
# 실행 중 네트워크 없음(폐쇄망). 가중치 파일 해시는 /model/SHA256SUMS, 출처는 /model/PROVENANCE.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.8.0 \
 && pip install --no-cache-dir transformers==4.56.2 huggingface_hub==0.35.3 safetensors
ARG MODEL=Qwen/Qwen3Guard-Gen-0.6B
ARG REVISION=fada3b2f655b89601929198343c94cd2f64d93cc
RUN HF_HUB_OFFLINE=0 python -c "from huggingface_hub import snapshot_download; snapshot_download('${MODEL}', revision='${REVISION}', local_dir='/model', allow_patterns=['*.json', '*.safetensors', '*.txt', 'LICENSE'])" \
 && rm -rf /model/.cache && cd /model && sha256sum $(ls | sort) > SHA256SUMS \
 && echo "${MODEL} ${REVISION} Apache-2.0" > PROVENANCE
# 허브 LFS 해시(고정 커밋의 model.safetensors)와 다르면 빌드 실패
ARG WEIGHTS_SHA256=4f3ce47ebd968cddb67de08d8764f8ede7c410a7d1fb9e08145a4c7a2f2e5c0f
RUN cd /model && echo "${WEIGHTS_SHA256}  model.safetensors" | sha256sum -c -
COPY server.py /srv/server.py
RUN useradd -r -u 10001 app
USER app
EXPOSE 8080
CMD ["python", "/srv/server.py"]
