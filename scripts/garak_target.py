"""garak 대상 (Epic 59) — garak REST 생성기가 부르는 '모델'. 모델 자체는 일부러 무방비(입력을 그대로 되돌림, garak test.Repeat 과 같음)이고,
그 앞뒤에 AegisMesh 입력·출력 관문을 둔다. 차단·승인 필요 = 거절 문구, 변환 = 변환된 출력. compose 서비스 garak-target(local, 프로파일 garak).

  POST /chat  {"prompt": "..."} → {"text": "...", "verdict": "..."}
env: GARAK_AEGIS_API(기본 http://api:8000) · GARAK_AEGIS_TOKEN(make garak-scan 이 만든 서비스 계정 토큰, 비커밋) · GARAK_TARGET(보호 대상 이름)
"""
from __future__ import annotations

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = os.environ.get("GARAK_AEGIS_API", "http://api:8000").rstrip("/")
TOKEN = os.environ.get("GARAK_AEGIS_TOKEN", "")
TARGET = os.environ.get("GARAK_TARGET", "garak.demo")
REFUSAL = "I can't help with that request."


def judge(gate: str, request: dict) -> dict:
    body = json.dumps({"gate": gate, "target": TARGET, "request": request}).encode()
    req = urllib.request.Request(f"{API}/v1/judge:batch", data=body, method="POST",
                                 headers={"content-type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def respond(prompt: str) -> dict:
    j = judge("input", {"text": prompt})
    if j["verdict"] in ("block", "require_approval"):
        return {"text": REFUSAL, "verdict": f"input:{j['verdict']}"}
    out = prompt                                                         # 무방비 모델 = 되풀이
    j = judge("output", {"output": out})
    if j["verdict"] in ("block", "require_approval"):
        return {"text": REFUSAL, "verdict": f"output:{j['verdict']}"}
    t = j.get("transformed")
    if j["verdict"] == "transform" and t:
        out = t.get("output", out) if isinstance(t, dict) else str(t)
    return {"text": out, "verdict": f"output:{j['verdict']}"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        try:
            prompt = json.loads(self.rfile.read(n) or b"{}").get("prompt", "")
            data, code = respond(str(prompt)), 200
        except Exception as e:  # noqa: BLE001 — garak 이 실패를 '응답 없음'으로 세게 한다
            data, code = {"error": str(e)[:200]}, 502
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802 — 헬스
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
