"""D9-02 서버 침해 — 런타임 침해 지표는 모두 차단(호스트 자동 격리 대상)."""
from aegis.decide import decide

VM = {k: "block" for k in ("app-spawned-shell", "cryptominer", "system-write", "c2-connect", "integrity-change")}
RULES = {f"D9-02.{k}": f"런타임 침해 지표 '{k}'. 차단·호스트 격리." for k in VM} | {"D9-02.pass": "런타임 이벤트 점검 통과."}


def detect(req, engine):
    return decide("D9-02", engine.scan(req), VM, rules=len(VM))
