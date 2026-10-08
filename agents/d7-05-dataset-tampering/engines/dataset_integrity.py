"""기본 엔진: 데이터셋 콘텐츠 해시·변경 승인·분포 이동·급증 (FR-D7-05).
artifact = {kind: dataset, name, version, contentHash, pinnedHash, changeApproved, labelDist: {..}, baselineLabelDist: {..}, rows, baselineRows}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "dataset_integrity"


def scan(req: JudgeRequest):
    a = artifact_of(req, "dataset")
    if not a:
        return []
    out = []
    pinned = a.get("pinnedHash") or req.params.get("pinnedHash")
    if pinned and a.get("contentHash") != pinned and not a.get("changeApproved"):
        out.append(signal("unapproved-change", 0.95, "critical", "artifact.contentHash", "콘텐츠 해시가 고정값과 다르고 변경 승인 없음"))
    cur, base = a.get("labelDist") or {}, a.get("baselineLabelDist") or {}
    if cur and base:
        tv = 0.5 * sum(abs(cur.get(k, 0) - base.get(k, 0)) for k in set(cur) | set(base))
        if tv > req.params.get("maxLabelShift", 0.2):
            out.append(signal("label-shift", 0.8, "medium", "artifact.labelDist", f"레이블 분포 이동 TV={tv:.2f} — 오염 의심"))
    if a.get("baselineRows") and a.get("rows", 0) > a["baselineRows"] * (1 + req.params.get("maxGrowth", 0.5)):
        out.append(signal("row-spike", 0.75, "medium", "artifact.rows", f"행 수 급증 {a['baselineRows']}→{a['rows']}"))
    return out
