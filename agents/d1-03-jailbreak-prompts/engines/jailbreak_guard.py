"""깊은 검사 엔진 (Epic 50 · OQ9 · FR-D1-03 확장): 탈옥 코퍼스 규칙 + 소형 분류기 + 안전 분류 모델(Qwen3Guard-Gen, compose guard).

인라인 기본 엔진(jailbreak_classifier)은 그대로 두고, 이 엔진은 응답 뒤 비동기 깊은 검사(app/gating.run_deep)와 공개 코퍼스 실측에서 쓴다.
안전 분류 모델이 사용자 입력(text)의 위험 확률을 GUARD_UNSAFE_MIN 이상으로 보면 guard(경보) — 비동기라 차단하지 않는다.
모델 서버 연결 실패는 예외로 올린다(에이전트 failMode·비동기 경로가 실패로 센다). GUARD_URL 이 없으면 jailbreak_classifier 와 같다.
TLS_DIR 이 있으면 내부 CA·클라이언트 인증서로 상호 TLS(prod, NFR-D3).
"""
import json
import os
import ssl
import urllib.request
from functools import lru_cache

from aegis.engine import Signal, sibling
from aegis.schemas import EvidenceItem, JudgeRequest

id = "jailbreak_guard"
base = sibling(__file__, "jailbreak_classifier")


def _ctx() -> ssl.SSLContext | None:
    d = os.environ.get("TLS_DIR")
    if not d:
        return None
    ctx = ssl.create_default_context(cafile=f"{d}/ca.crt")
    ctx.load_cert_chain(f"{d}/tls.crt", f"{d}/tls.key")
    return ctx


@lru_cache(maxsize=4096)                     # 같은 입력 반복(간접 주입 요약 요청 등)은 다시 묻지 않는다 — 메모리에만, 저장 안 함
def classify(text: str) -> dict:
    req = urllib.request.Request(f"{os.environ['GUARD_URL'].rstrip('/')}/classify", data=json.dumps({"text": text}).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=float(os.environ.get("GUARD_TIMEOUT_SEC", "30")), context=_ctx()) as r:
        return json.load(r)


def risk(g: dict) -> float:
    return g["p"]["Unsafe"]


def scan(req: JudgeRequest) -> list[Signal]:
    out = base.scan(req)
    if not os.environ.get("GUARD_URL"):
        return out
    floor = float(os.environ.get("GUARD_UNSAFE_MIN", "0.5"))
    for loc, text in req.texts("text"):
        g = classify(text)
        if risk(g) >= floor:
            out.append(Signal(rule="guard", score=round(risk(g), 3), severity="high",
                              evidence=EvidenceItem(kind="span", location=loc, offset=0, length=len(text),
                                                    note=f"안전 분류 모델 {g['safety']} · 위험 {risk(g):.2f} · 범주 {', '.join(g['categories']) or '—'}")))
    return out


def explain(req: JudgeRequest) -> dict:
    out = base.explain(req)
    if os.environ.get("GUARD_URL"):
        out["guard"] = {"floor": float(os.environ.get("GUARD_UNSAFE_MIN", "0.5")),
                        "inputs": [{"location": loc, **classify(t)} for loc, t in req.texts("text")]}
    return out
