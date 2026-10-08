# 인라인 주입 분류 모델 서버 (Epic 64 · NFR-Q2 인라인 · OQ9) — protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0, 비게이트)
# 고정 커밋의 ONNX 판을 이미지 빌드 때만 받는다(실행 중 네트워크 없음). 해시는 /model/SHA256SUMS, 출처는 /model/PROVENANCE.
# CPU ONNX Runtime — 짧은 입력 ≈10 ms·110 토큰 ≈70 ms·512 토큰 ≈370 ms(측정). 인라인은 앞·뒤로 자른 짧은 창만 본다.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
RUN pip install --no-cache-dir onnxruntime==1.22.1 tokenizers==0.22.1 numpy==2.3.3 huggingface_hub==0.35.3
ARG MODEL=protectai/deberta-v3-base-prompt-injection-v2
ARG REVISION=90c9989b1a342275dd0d1a95aad283c04e075671
RUN HF_HUB_OFFLINE=0 python -c "from huggingface_hub import snapshot_download; snapshot_download('${MODEL}', revision='${REVISION}', local_dir='/model', allow_patterns=['config.json', 'tokenizer.json', 'onnx/model.onnx', 'LICENSE'])" \
 && rm -rf /model/.cache && cd /model && sha256sum config.json tokenizer.json onnx/model.onnx > SHA256SUMS && echo "${MODEL} ${REVISION} Apache-2.0" > PROVENANCE
# 허브의 고정 커밋 ONNX 해시와 다르면 빌드 실패
ARG ONNX_SHA256=f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c
RUN cd /model && echo "${ONNX_SHA256}  onnx/model.onnx" | sha256sum -c -
COPY server.py /srv/server.py
RUN useradd -r -u 10001 app
USER app
EXPOSE 8080
CMD ["python", "/srv/server.py"]
