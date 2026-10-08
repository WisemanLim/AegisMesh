"""OpenAPI 계약 적합성 (COMPLIANCE 추가 시험) — 기록된 계약 대비 깨지는 변경(작업 삭제·필수 매개변수·필수 본문 필드 추가·매개변수 삭제)을 막는다.
추가는 허용. 의도한 변경이면 `make contract-update` 로 스냅샷을 갱신하고 리뷰에서 diff 를 본다."""
import json
from pathlib import Path

from scripts.contract_snapshot import OUT, current


def _req(xs):
    return {x.rstrip("!") for x in xs if x.endswith("!")}


def _names(xs):
    return {x.rstrip("!") for x in xs}


def test_no_breaking_changes():
    old = json.loads(Path(OUT).read_text())["operations"]
    new = current()["operations"]
    broken = []
    for op, o in old.items():
        n = new.get(op)
        if n is None:
            broken.append(f"{op}: 작업 삭제")
            continue
        if gone := _names(o["params"]) - _names(n["params"]):
            broken.append(f"{op}: 매개변수 삭제 {sorted(gone)}")
        if added := _req(n["params"]) - _req(o["params"]):
            broken.append(f"{op}: 필수 매개변수 추가 {sorted(added)}")
        if added := _req(n["bodyFields"]) - _req(o["bodyFields"]):
            broken.append(f"{op}: 필수 본문 필드 추가 {sorted(added)}")
        if n["bodyRequired"] and not o["bodyRequired"]:
            broken.append(f"{op}: 본문이 필수로 바뀜")
    assert not broken, "깨지는 계약 변경 — 의도했다면 make contract-update:\n" + "\n".join(broken)


def test_contract_shape():
    ops = current()["operations"]
    assert len(ops) >= 200
    untagged = [k for k, o in ops.items() if " /v1/" in k and not o["tags"]]          # 상태 점검(/health·/readyz)은 계약 밖
    assert not untagged, untagged
    for key in ("POST /v1/judge:batch", "GET /v1/evidence:verify", "POST /v1/approvals/{aid}:decide", "GET /v1/metrics/success"):
        assert key in ops, key
