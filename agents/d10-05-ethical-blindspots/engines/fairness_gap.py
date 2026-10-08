"""기본 엔진: 집단별 성능 분해 — 오탐률·탐지율 격차(4/5 규칙) + 집단별 차단율 격차(%p) (FR-D10-05).
artifact.fairness = [{group, fpr, tpr, n}] · artifact.blockRates = [{axis, group, n, rate}] (가명·집계만)"""
from aegis.engine import artifact_of, signal

id = "fairness_gap"


def scan(req):
    a = artifact_of(req, "governance_snapshot")
    if not a or ("fairness" not in a and "blockRates" not in a):
        return []
    out, rated = _block_gaps(a.get("blockRates") or [], req.params)
    groups = [g for g in a.get("fairness") or [] if g.get("n", 0) >= req.params.get("minGroupSize", 30)]
    if not groups:
        return out if rated else [signal("not-measured", 0.7, "low", "artifact.fairness", "집단별 성능 측정 없음(표본 부족)")]
    fprs = [g["fpr"] for g in groups if g.get("fpr") is not None]
    if len(fprs) >= 2 and min(fprs) > 0 and max(fprs) / min(fprs) > req.params.get("maxRatio", 1.25):
        worst = max(groups, key=lambda g: g.get("fpr", 0))
        out.append(signal("fpr-disparity", 0.82, "medium", "artifact.fairness", f"집단 간 오탐률 격차 {max(fprs) / min(fprs):.2f}배 (최악 {worst['group']})"))
    tprs = [g["tpr"] for g in groups if g.get("tpr") is not None]
    if len(tprs) >= 2 and max(tprs) > 0 and min(tprs) / max(tprs) < 0.8:
        out.append(signal("tpr-disparity", 0.8, "medium", "artifact.fairness", f"집단 간 탐지율 비 {min(tprs) / max(tprs):.2f} < 0.8"))
    return out


def _block_gaps(rates: list[dict], params: dict) -> tuple[list, bool]:
    """같은 축(연령·언어·지역·채널 …) 안에서 표본이 충분한 집단끼리 차단율 차이(%p)가 한도를 넘으면 경보.
    두 번째 값 = 비교 가능한 축(표본 충분 집단 2개 이상)이 하나라도 있었는지(= 측정됨)."""
    by: dict[str, list[dict]] = {}
    for r in rates:
        if r.get("n", 0) >= params.get("minGroupSize", 30) and r.get("rate") is not None:
            by.setdefault(str(r.get("axis", "group")), []).append(r)
    out, rated = [], False
    lim = params.get("maxGapPp", 1.5)
    for axis, gs in sorted(by.items()):
        if len(gs) < 2:
            continue
        rated = True
        hi, lo = max(gs, key=lambda g: g["rate"]), min(gs, key=lambda g: g["rate"])
        gap = (hi["rate"] - lo["rate"]) * 100
        if gap > lim:
            out.append(signal("block-rate-gap", 0.8, "medium", f"artifact.blockRates.{axis}",
                              f"{axis} 집단 차단율 격차 {gap:.2f}%p > {lim}%p ({hi['group']} {hi['rate'] * 100:.2f}% · {lo['group']} {lo['rate'] * 100:.2f}%)"))
    return out, rated
