"""D5-07 권한 불일치 — 와일드카드·에이전트 > 소유자는 차단(회수), 미사용 고권한은 경보(최소 권한)."""
from aegis.decide import decide

VM = {"wildcard-grant": "block", "agent-exceeds-owner": "block", "unused-privileged": "alert"}
RULES = {f"D5-07.{k}": f"권한 인벤토리 점검 '{k}' → {v}." for k, v in VM.items()} | {"D5-07.pass": "권한 정합성 점검 통과."}


def detect(req, engine):
    return decide("D5-07", engine.scan(req), VM, rules=len(VM))
