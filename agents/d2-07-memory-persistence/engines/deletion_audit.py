"""기본 엔진: 삭제 전파 감사(원본·인덱스·캐시·백업) + 메모리 TTL 초과 잔존 (FR-D2-07, NFR-D4).
artifact.kind = deletion_audit: {subject, requestedAt, stores: {primary: bool(잔존), index: …, cache: …, memory: …, backup: …}}"""
import time

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "deletion_audit"
STORES = ("primary", "index", "cache", "memory", "backup")


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    now = req.params.get("now", time.time())
    a = req.artifact or {}
    if a.get("kind") == "deletion_audit":
        grace = req.params.get("backupGraceSec", 30 * 86400)
        for st in STORES:
            if a.get("stores", {}).get(st):
                late = st == "backup" and now - a.get("requestedAt", now) <= grace
                out.append(Signal(rule="residual-copy", score=0.3 if late else 0.93, severity="info" if late else "high",
                                  evidence=EvidenceItem(kind="store", location=f"artifact.stores.{st}",
                                                        note=f"삭제 요청 후 {st} 에 사본 잔존" + (" (백업 유예 기간 내)" if late else ""))))
        if not a.get("receiptIssued", False):
            out.append(Signal(rule="no-receipt", score=0.7, severity="medium",
                              evidence=EvidenceItem(kind="store", location="artifact.receiptIssued", note="삭제 증적 미발행")))
    default_ttl = req.params.get("defaultTtlDays")
    for m in req.memory:
        ttl = m.ttl_sec if m.ttl_sec is not None else (default_ttl * 86400 if default_ttl else None)
        if ttl is not None and m.created_at is not None and m.created_at + ttl < now:
            out.append(Signal(rule="ttl-expired", score=0.8, severity="medium", evidence=EvidenceItem(
                kind="memory", location=f"memory:{m.id}",
                note=f"TTL {ttl}초 경과 후 잔존" + ("" if m.ttl_sec is not None else " (기본 TTL)"))))
    return out
