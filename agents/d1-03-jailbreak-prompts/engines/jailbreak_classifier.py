"""이중 판정 엔진 (FR-D1-03 "탈옥 코퍼스 유사도 매칭 + 전용 분류기", OQ4): 코퍼스 규칙 + 소형 분류기.

규칙 신호는 그대로 낸다. 분류기는 사용자 입력(text)의 점수를 내고, 경보 임계 이상이면 classifier(경보)·차단 임계 이상이면
classifier-block(차단). 모델 해시가 다르면 적재를 거부한다.
"""
from aegis.classifier import load
from aegis.engine import Signal, sibling
from aegis.schemas import EvidenceItem, JudgeRequest

id = "jailbreak_classifier"
MODEL = "injection-clf-v1"
MODEL_SHA256 = "95eb538fa09cf0be30aa99a1d4034c09f352340fedac2d616bfbd9199682766a"
rules = sibling(__file__, "jailbreak_corpus")


def _model():
    return load(MODEL, MODEL_SHA256)


try:                                     # 기동 시 미리 적재(첫 판정 지연 제거). 실패는 판정 때 드러나 failMode 로 처리된다
    _model()
except Exception:  # noqa: BLE001
    pass


def scan(req: JudgeRequest) -> list[Signal]:
    out = rules.scan(req)
    ruled = {sg.evidence.location for sg in out}
    m = _model()
    for loc, text in req.texts("text"):
        p = m.prob(text)
        if p >= m.thresholds["alert"]:
            block = p >= m.thresholds["block"]
            # 같은 위치에 규칙 신호가 있으면 규칙이 주 근거 — 분류기 점수는 근거 메모에 그대로 두고 순위만 낮춘다
            score = round(p, 3) if loc not in ruled else min(round(p, 3), 0.79)
            out.append(Signal(rule="classifier-block" if block else "classifier", score=score, severity="high" if block else "medium",
                              evidence=EvidenceItem(kind="span", location=loc, offset=0, length=len(text),
                                                    note=f"분류기 점수 {p:.2f} · 모델 {m.version}")))
    return out


def explain(req: JudgeRequest) -> dict:
    out = rules.explain(req)
    m = _model()
    out["classifier"] = {"model": m.version, "sha256": m.sha256[:12], "thresholds": m.thresholds,
                         "inputs": [{"location": loc, "score": round(m.prob(t), 3), "top": m.top(t, 5)} for loc, t in req.texts("text")]}
    return out
