"""기본 엔진: 메모리 쓰기 승인 정책 + 장기 행동 유도 문구 + 이상 변동 (FR-D8-02)."""
import re

from aegis.engine import signal
from aegis.schemas import JudgeRequest

id = "memory_drift"
PERSIST = re.compile(r"(\balways\b.{0,40}\b(when|whenever|from now)|\bremember (to|that) (always|never)\b|\bin (all|every) future (sessions?|conversations?)\b"
                     r"|앞으로\s*(항상|모든)|매번\s*.{0,20}(하라|해라|할 것)|다음\s*세션(에서도|부터))", re.I)


def scan(req: JudgeRequest):
    out = []
    need_approval = req.params.get("memoryWriteApproval", False)
    writers: dict[str, int] = {}
    for m in req.memory:
        if (x := PERSIST.search(m.text)):
            out.append(signal("persistent-directive", 0.78, "medium", f"memory:{m.id}", "장기 행동을 유도하는 메모리 문구", "memory",
                              x.start(), x.end() - x.start()))
        if need_approval and m.writer and m.writer != "user" and m.approved is not True:
            out.append(signal("unapproved-write", 0.9, "high", f"memory:{m.id}", f"승인 없이 {m.writer} 가 쓴 메모리", "memory"))
        if m.writer:
            writers[m.writer] = writers.get(m.writer, 0) + 1
    burst = req.params.get("maxWritesPerWriter", 20)
    for w, n in writers.items():
        if n > burst:
            out.append(signal("write-burst", 0.75, "medium", "memory", f"{w} 의 메모리 쓰기 {n}건 — 이상 변동", "memory"))
    return out
