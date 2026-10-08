"""인라인 주입 분류 모델 서버 (Epic 64) — ONNX Runtime CPU.

  POST /classify {"text": "...", "window": 128}  → {"injection": 확률, "ms", "tokens", "windowed"}
  GET  /health                                    → 모델·스레드·처리 수

window(토큰)를 주면 앞·뒤 절반씩만 본다(인라인 예산 — 지시 덮어쓰기는 대개 처음이나 끝). 0 이면 512 토큰까지.
입력 원문은 기록하지 않는다. 스레드 INJGUARD_THREADS(기본 4).
"""
import json
import os
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

TOK = Tokenizer.from_file("/model/tokenizer.json")
TOK.no_truncation()                                                     # 저장된 512 자르기를 끈다 — 앞·뒤 창을 직접 고른다
TOK.no_padding()
CFG = json.load(open("/model/config.json"))
INJ = next((int(k) for k, v in CFG.get("id2label", {}).items() if v.upper() == "INJECTION"), 1)
OPT = ort.SessionOptions()
OPT.intra_op_num_threads = int(os.environ.get("INJGUARD_THREADS", "4"))
OPT.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
SESS = ort.InferenceSession("/model/onnx/model.onnx", OPT, providers=["CPUExecutionProvider"])
NAMES = {i.name for i in SESS.get_inputs()}
STATS = {"classified": 0, "ms": 0.0}


def classify(text: str, window: int = 0) -> dict:
    ids = TOK.encode(text[:40000]).ids                                   # [CLS] … [SEP]
    limit = min(window or 512, 512)
    windowed = len(ids) > limit
    if windowed:
        half = (limit - 2) // 2
        ids = ids[:1 + half] + ids[-(limit - 2 - half) - 1:]             # 앞 [CLS]+절반 · 뒤 절반+[SEP]
    feed = {"input_ids": np.array([ids], dtype=np.int64), "attention_mask": np.ones((1, len(ids)), dtype=np.int64)}
    if "token_type_ids" in NAMES:
        feed["token_type_ids"] = np.zeros((1, len(ids)), dtype=np.int64)
    logits = SESS.run(None, {k: v for k, v in feed.items() if k in NAMES})[0][0]
    e = np.exp(logits - logits.max())
    return {"injection": round(float(e[INJ] / e.sum()), 4), "tokens": len(ids), "windowed": windowed}


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        self._send(200, {"ok": True, "model": open("/model/PROVENANCE").read().strip(), "threads": OPT.intra_op_num_threads} | STATS)

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        t0 = time.perf_counter()
        out = classify(str(body.get("text", "")), int(body.get("window") or 0))
        ms = (time.perf_counter() - t0) * 1000
        STATS["classified"] += 1
        STATS["ms"] += ms
        self._send(200, out | {"ms": round(ms, 2)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), H)
    d = os.environ.get("TLS_DIR")
    if d:                                                               # prod 상호 TLS(NFR-D3) — 내부 CA 클라이언트 인증서 필수
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{d}/ca.crt")
        ctx.load_cert_chain(f"{d}/tls.crt", f"{d}/tls.key")
        ctx.verify_mode = ssl.CERT_REQUIRED
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    classify("hello", 96)                                               # 예열
    print(f"injguard ready — threads {OPT.intra_op_num_threads} tls={bool(d)}", flush=True)
    srv.serve_forever()
