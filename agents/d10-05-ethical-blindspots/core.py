"""D10-05 윤리 맹점 — 집단별 성능 격차·미측정은 경보(영향 평가 문서화 요구)."""
from aegis.decide import decide

VM = {"not-measured": "alert", "fpr-disparity": "alert", "tpr-disparity": "alert", "block-rate-gap": "alert"}
RULES = {f"D10-05.{k}": f"공정성 점검 '{k}' → 경보." for k in VM} | {"D10-05.pass": "집단별 성능 격차 기준 이내."}


def detect(req, engine):
    return decide("D10-05", engine.scan(req), VM, rules=len(VM))
