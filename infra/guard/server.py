"""안전 분류 모델 서버 (Epic 50 · OQ9) — Qwen3Guard-Gen 으로 사용자 입력 하나의 안전 등급·범주를 낸다. 입력은 저장하지 않는다.

  POST /classify {"text": "..."} → {"safety": "Safe|Controversial|Unsafe", "p": {등급: 확률}, "categories": [...], "ms": 12.3}
  GET  /health → {"ok": true, "model": ..., "revision": ...}

TLS_DIR 이 있으면(prod) 내부 CA 로 서명된 클라이언트 인증서를 요구한다(NFR-D3 상호 TLS). 추론은 한 번에 하나(잠금).
"""
from __future__ import annotations

import copy
import json
import os
import re
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_DIR = "/model"
MAX_CHARS = 4000                                     # 긴 입력은 앞 3,000 + 뒤 1,000 자 (지연 상한)
SAFE = re.compile(r"Safety: (Safe|Unsafe|Controversial)")
CATS = re.compile(r"(Violent|Non-violent Illegal Acts|Sexual Content or Sexual Acts|PII|Suicide & Self-Harm|Unethical Acts|"
                  r"Politically Sensitive Topics|Copyright Violation|Jailbreak|None)")
torch.set_num_threads(int(os.environ.get("GUARD_THREADS", "8")))
tok = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForCausalLM.from_pretrained(MODEL_DIR, dtype=torch.float32).eval()
lock = threading.Lock()
PROV = Path(MODEL_DIR, "PROVENANCE").read_text().split()
SERVED = {"classified": 0}                              # 처리 건수만(입력은 남기지 않는다) — 처리량 실측용


LABELS = {"Safe": " Safe", "Unsafe": " Unsafe", "Controversial": " Controversial"}
FIRST = {k: tok.encode(v, add_special_tokens=False)[0] for k, v in LABELS.items()}      # 등급 이름의 첫 토큰


def _prompt(text: str) -> str:
    if len(text) > MAX_CHARS:
        text = text[:3000] + "\n…\n" + text[-1000:]
    return tok.apply_chat_template([{"role": "user", "content": text}], tokenize=False)   # assistant 머리(빈 think)까지 포함


# 모델 카드 지시문의 고정 앞부분(정책·범주 설명, 약 200 토큰)은 KV 캐시로 한 번만 계산한다 — 요청마다 사용자 문장 + 뒤 지시만 처리
_MARK = "\x00MARK\x00"
_PRE_TEXT = _prompt(_MARK).split(_MARK)[0]
_PRE_IDS = tok(_PRE_TEXT, return_tensors="pt").input_ids
with torch.inference_mode():
    _PRE_KV = model(input_ids=_PRE_IDS, use_cache=True).past_key_values


def _last_logits(prompt: str) -> torch.Tensor:
    assert prompt.startswith(_PRE_TEXT)
    rest = tok(prompt[len(_PRE_TEXT):], add_special_tokens=False, return_tensors="pt").input_ids
    attn = torch.ones(1, _PRE_IDS.shape[1] + rest.shape[1], dtype=torch.long)
    return model(input_ids=rest, past_key_values=copy.deepcopy(_PRE_KV), attention_mask=attn, use_cache=True).logits[0, -1]


def classify(text: str, generate: bool = False, categories: bool = True) -> dict:
    """기본 = 순전파 1회: 출력은 항상 'Safety: <등급>' 으로 시작하므로 'Safety:' 뒤 첫 토큰의 확률을 세 등급끼리 비교한다.
    위험·논란이면 범주만 짧게 생성한다(categories=False 면 생략 — 대량 실측용). generate=True 는 모델 카드 방식(전체 생성) — 대조 검증용."""
    t0 = time.perf_counter()
    prompt = _prompt(text)
    with lock, torch.inference_mode():
        if generate:
            ids = tok([prompt], return_tensors="pt")
            out = model.generate(**ids, max_new_tokens=24, do_sample=False)
            content = tok.decode(out[0][ids.input_ids.shape[1]:], skip_special_tokens=True)
            m = SAFE.search(content)
            return {"safety": m.group(1) if m else None, "categories": [c for c in CATS.findall(content) if c != "None"],
                    "ms": round((time.perf_counter() - t0) * 1000, 1), "mode": "generate"}
        logits = _last_logits(prompt + "Safety:")
        p = torch.softmax(torch.stack([logits[i] for i in FIRST.values()]), dim=0).tolist()
        probs = dict(zip(FIRST, p))
        label = max(probs, key=probs.get)
        cats: list[str] = []
        if label != "Safe" and categories:
            ids2 = tok([prompt + "Safety:" + LABELS[label] + "\nCategories:"], return_tensors="pt")
            out = model.generate(**ids2, max_new_tokens=12, do_sample=False)
            cats = [c for c in CATS.findall(tok.decode(out[0][ids2.input_ids.shape[1]:], skip_special_tokens=True)) if c != "None"]
    return {"safety": label, "p": {k: round(v, 4) for k, v in probs.items()}, "categories": cats,
            "ms": round((time.perf_counter() - t0) * 1000, 1), "mode": "fast"}


class H(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True, "model": PROV[0], "revision": PROV[1], **SERVED})
        self._send(404, {"detail": "not found"})

    def do_POST(self):
        if self.path != "/classify":
            return self._send(404, {"detail": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0)) or 0))
            text = str(body["text"])
        except (ValueError, KeyError, TypeError):
            return self._send(422, {"detail": "body {text} 필요"})
        out = classify(text, bool(body.get("generate")), body.get("categories", True) is not False)
        with lock:
            SERVED["classified"] += 1
        self._send(200, out)

    def log_message(self, *_):                          # 입력 내용을 로그에 남기지 않는다
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), H)
    d = os.environ.get("TLS_DIR")
    if d:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{d}/ca.crt")
        ctx.load_cert_chain(f"{d}/tls.crt", f"{d}/tls.key")
        ctx.verify_mode = ssl.CERT_REQUIRED
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    classify("hello")                                    # 예열
    print(f"guard ready — {PROV[0]}@{PROV[1][:12]} tls={bool(d)}", flush=True)
    srv.serve_forever()
