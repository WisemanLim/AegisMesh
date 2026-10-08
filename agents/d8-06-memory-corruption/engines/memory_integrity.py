"""기본 엔진: 메모리 레코드 체크섬·중복 충돌 (FR-D8-06). checksum = sha256(text) 16진."""
import hashlib

from aegis.engine import signal
from aegis.schemas import JudgeRequest

id = "memory_integrity"


def scan(req: JudgeRequest):
    out = []
    seen: dict[str, str] = {}
    for m in req.memory:
        if m.checksum and hashlib.sha256(m.text.encode()).hexdigest() != m.checksum:
            out.append(signal("checksum-mismatch", 0.95, "high", f"memory:{m.id}", "체크섬 불일치 — 부분 손상·변조", "memory"))
        if m.id in seen and seen[m.id] != m.text:
            out.append(signal("conflict", 0.8, "medium", f"memory:{m.id}", "같은 ID 레코드가 서로 다른 내용으로 중복", "memory"))
        seen.setdefault(m.id, m.text)
    return out
