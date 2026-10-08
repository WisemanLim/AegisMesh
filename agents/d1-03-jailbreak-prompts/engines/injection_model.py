"""인라인 주입 분류 모델 엔진 (Epic 64 · NFR-Q2 인라인 · OQ9): 탈옥 코퍼스 규칙 + 소형 분류기 + 주입 분류 모델(injguard, compose).

모델 = protectai/deberta-v3-base-prompt-injection-v2(Apache-2.0) 고정 커밋 ONNX, CPU. 인라인 예산 때문에 입력의 앞·뒤 INJGUARD_WINDOW 토큰만 본다.
INJGUARD_TIMEOUT_MS 안에 답이 없거나 서버 장애면 모델 신호 없이 이중 판정(jailbreak_classifier)과 같다 — 인라인 관문을 막지 않는다
(전체 입력은 응답 뒤 깊은 검사가 본다). 확률 ≥ INJGUARD_BLOCK 차단(model-block) · ≥ INJGUARD_ALERT 경보(model).
같은 위치에 규칙 신호가 있으면 규칙이 주 근거. INJGUARD_URL 이 없으면 jailbreak_classifier 와 같다. TLS_DIR 이 있으면 상호 TLS.
모델은 영어 학습 — 한국어 등 비라틴 문자 입력은 정상 문장도 주입으로 본다(실측 0.998+). 글자 중 라틴 비율이 LATIN_MIN 미만이면
모델을 묻지 않고 이중 판정만(규칙·분류기는 한국어 포함) — 다국어 모델로 바꿀 때까지의 한계.
"""
import json
import os
import ssl
import urllib.request
from functools import lru_cache

from aegis.engine import Signal, sibling
from aegis.schemas import EvidenceItem, JudgeRequest

id = "injection_model"
base = sibling(__file__, "jailbreak_classifier")
STATS = {"asked": 0, "timeouts": 0, "errors": 0, "skipped": 0}
LATIN_MIN = 0.8


def latin(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    return not letters or sum(c < "\u0250" for c in letters) / len(letters) >= LATIN_MIN


def _ctx() -> ssl.SSLContext | None:
    d = os.environ.get("TLS_DIR")
    if not d:
        return None
    ctx = ssl.create_default_context(cafile=f"{d}/ca.crt")
    ctx.load_cert_chain(f"{d}/tls.crt", f"{d}/tls.key")
    return ctx


@lru_cache(maxsize=4096)                     # 같은 입력 반복은 다시 묻지 않는다 — 메모리에만
def classify(text: str) -> dict:
    body = json.dumps({"text": text, "window": int(os.environ.get("INJGUARD_WINDOW", "96"))}).encode()
    req = urllib.request.Request(f"{os.environ['INJGUARD_URL'].rstrip('/')}/classify", data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=float(os.environ.get("INJGUARD_TIMEOUT_MS", "60")) / 1000, context=_ctx()) as r:
        return json.load(r)


def _ask(text: str) -> dict | None:
    if not latin(text):
        STATS["skipped"] += 1
        return None
    STATS["asked"] += 1
    try:
        return classify(text)
    except TimeoutError:
        STATS["timeouts"] += 1
    except OSError as e:
        STATS["timeouts" if "timed out" in str(e) else "errors"] += 1
    return None


def scan(req: JudgeRequest) -> list[Signal]:
    out = base.scan(req)
    if not os.environ.get("INJGUARD_URL"):
        return out
    alert, block = float(os.environ.get("INJGUARD_ALERT", "0.95")), float(os.environ.get("INJGUARD_BLOCK", "0.999"))
    ruled = {sg.evidence.location for sg in out}
    for loc, text in req.texts("text"):
        g = _ask(text)
        if g is None or g["injection"] < alert:
            continue
        hard = g["injection"] >= block
        score = round(g["injection"], 3) if loc not in ruled else min(round(g["injection"], 3), 0.79)
        out.append(Signal(rule="model-block" if hard else "model", score=score, severity="high" if hard else "medium",
                          evidence=EvidenceItem(kind="span", location=loc, offset=0, length=len(text),
                                                note=f"주입 분류 모델 {g['injection']:.3f} · 창 {g['tokens']} 토큰{' (앞·뒤)' if g.get('windowed') else ''}")))
    return out


def explain(req: JudgeRequest) -> dict:
    out = base.explain(req)
    if os.environ.get("INJGUARD_URL"):
        out["injectionModel"] = {"alert": float(os.environ.get("INJGUARD_ALERT", "0.95")), "block": float(os.environ.get("INJGUARD_BLOCK", "0.999")),
                                 "stats": dict(STATS), "inputs": [{"location": loc, **(_ask(t) or {"unavailable": True, "latin": latin(t)})} for loc, t in req.texts("text")]}
    return out
