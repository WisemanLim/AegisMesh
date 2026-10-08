"""기본 엔진: 관측 파이프라인 설정·로그 표본 점검 (FR-D2-06). artifact.kind = log_pipeline."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "log_pipeline_audit"

RAW_KEYS = ("gen_ai.prompt", "gen_ai.completion", "llm.prompts", "llm.output", "request.body", "messages")
SECRET = re.compile(r"(sk-(ant-|proj-)?[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.eyJ)")
RRN = re.compile(r"(?<!\d)\d{6}-?[1-8]\d{6}(?!\d)")


def scan(req: JudgeRequest) -> list[Signal]:
    a = req.artifact or {}
    if a.get("kind") != "log_pipeline":
        return []
    out: list[Signal] = []

    def sig(rule, score, sev, loc, note):
        out.append(Signal(rule=rule, score=score, severity=sev, evidence=EvidenceItem(kind="config", location=loc, note=note)))

    procs = [str(p).lower() for p in a.get("processors", [])]
    if not any("mask" in p or "redact" in p for p in procs):
        sig("no-masking", 0.85, "high", "artifact.processors", "수집 단계 마스킹 프로세서 없음")
    dropped = {str(k) for k in a.get("droppedAttributes", [])}
    kept = [k for k in RAW_KEYS if k in a.get("attributes", []) and k not in dropped]
    if kept:
        sig("raw-payload", 0.88, "high", "artifact.attributes", f"원문 속성 저장: {', '.join(kept)}")
    if a.get("retentionDays", 0) > req.params.get("maxRetentionDays", 90):
        sig("retention", 0.7, "medium", "artifact.retentionDays", f"보존 {a['retentionDays']}일 > 정책")
    if a.get("payloadAccess") in ("all", "everyone", "*"):
        sig("open-access", 0.8, "high", "artifact.payloadAccess", "페이로드 열람 권한 분리 없음")
    for i, rec in enumerate(a.get("sampleRecords", [])):
        if SECRET.search(str(rec)) or RRN.search(str(rec)):
            sig("secret-in-logs", 0.96, "critical", f"artifact.sampleRecords[{i}]", "로그 표본에 자격증명·주민번호 원문")
            break
    return out
