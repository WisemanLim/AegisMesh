"""관측 (FR-P09, NFR-O3) — 지표·추적·로그를 OpenTelemetry(OTLP/HTTP)로 내보낸다. 벤더 형식 없음.

- 추적: 관문 판정 1건 = 루트 span `aegis.gate.<gate>` + 에이전트별 하위 span. trace id = 판정 traceId(원장 레코드와 연결).
  비허용·강등·예산 초과 판정은 항상, allow 판정은 OTEL_ALLOW_TRACE_RATIO 비율만(trace id 로 정해 노드 간 일관). 지표는 표본 없이 전부.
- 지표: aegis.gate.requests · aegis.gate.duration(ms) · aegis.gate.degraded · aegis.findings.
- 로그: 비허용 판정 요약(규칙·판정·위치) — 원문·무해화 결과는 싣지 않는다(NFR-D1).
- 마스킹: 수집 단계(Collector transform 프로세서, observability/masking.yaml)에서 치환. 같은 규칙을 mask() 로 미리 본다.
OTEL_ENDPOINT 가 없으면 아무것도 내보내지 않는다(no-op).
"""
from __future__ import annotations

import contextvars
import logging
import re
import threading
import time
from functools import lru_cache
from pathlib import Path

import yaml
from opentelemetry import metrics, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.id_generator import RandomIdGenerator
from opentelemetry.trace import SpanKind, Status, StatusCode

from app.core.config import settings

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "observability" / "masking.yaml"
COLLECTOR = ROOT / "infra" / "otel" / "collector.yaml"
log = logging.getLogger("aegismesh.telemetry")

STATS: dict[str, dict] = {k: {"ok": 0, "failed": 0, "items": 0, "lastAt": None, "lastError": None} for k in ("traces", "metrics", "logs")}
_state = {"service": None, "enabled": False}
_lock = threading.Lock()
_pending_trace: contextvars.ContextVar[int | None] = contextvars.ContextVar("aegis_trace", default=None)


def _count(signal: str, ok: bool, n: int, err: str | None = None) -> None:
    with _lock:
        st = STATS[signal]
        st["ok" if ok else "failed"] += 1
        st["items"] += n
        st["lastAt"] = time.time()
        if err:
            st["lastError"] = err[:300]


class _TraceIds(RandomIdGenerator):
    """판정 traceId 를 그대로 OTel trace id 로 쓴다 — 원장·판정 조회와 추적이 같은 ID 로 이어진다."""

    def generate_trace_id(self) -> int:
        return _pending_trace.get() or super().generate_trace_id()


class _CountingSpans(SpanExporter):
    def __init__(self, inner: SpanExporter):
        self.inner = inner

    def export(self, spans):
        try:
            r = self.inner.export(spans)
        except Exception as exc:  # noqa: BLE001 — 관측 실패가 판정을 막지 않는다
            _count("traces", False, len(spans), repr(exc))
            return SpanExportResult.FAILURE
        _count("traces", r == SpanExportResult.SUCCESS, len(spans), None if r == SpanExportResult.SUCCESS else "export failure")
        return r

    def shutdown(self):
        self.inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000):
        return self.inner.force_flush(timeout_millis)


def setup(service: str, span_exporter: SpanExporter | None = None, metric_reader=None, log_exporter=None) -> bool:
    """프로세스당 1회. 시험은 메모리 내보내기를 넘긴다."""
    if _state["enabled"]:
        return True
    _state["service"] = service
    endpoint = (settings.otel_endpoint or "").rstrip("/")
    if not endpoint and span_exporter is None:
        return False
    res = Resource.create({"service.name": service, "service.version": "0.1.0", "service.namespace": "aegismesh",
                           "deployment.environment.name": settings.app_env})
    tp = TracerProvider(resource=res, id_generator=_TraceIds())
    if span_exporter is not None:
        tp.add_span_processor(SimpleSpanProcessor(_CountingSpans(span_exporter)))
    else:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        tp.add_span_processor(BatchSpanProcessor(_CountingSpans(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", timeout=5))))
    trace.set_tracer_provider(tp)
    from opentelemetry.sdk.metrics import MeterProvider
    if metric_reader is None:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        class _CountingMetrics(OTLPMetricExporter):
            def export(self, metrics_data, timeout_millis: float = 10_000, **kw):
                try:
                    r = super().export(metrics_data, timeout_millis, **kw)
                except Exception as exc:  # noqa: BLE001
                    _count("metrics", False, 0, repr(exc))
                    raise
                _count("metrics", r.name == "SUCCESS", len(metrics_data.resource_metrics))
                return r
        metric_reader = PeriodicExportingMetricReader(_CountingMetrics(endpoint=f"{endpoint}/v1/metrics", timeout=5),
                                                      export_interval_millis=15_000)
    metrics.set_meter_provider(MeterProvider(resource=res, metric_readers=[metric_reader]))
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, SimpleLogRecordProcessor
    lp = LoggerProvider(resource=res)
    if log_exporter is not None:
        lp.add_log_record_processor(SimpleLogRecordProcessor(log_exporter))
    else:
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

        class _CountingLogs(OTLPLogExporter):
            def export(self, batch):
                try:
                    r = super().export(batch)
                except Exception as exc:  # noqa: BLE001
                    _count("logs", False, len(batch), repr(exc))
                    raise
                _count("logs", r.name == "SUCCESS", len(batch))
                return r
        lp.add_log_record_processor(BatchLogRecordProcessor(_CountingLogs(endpoint=f"{endpoint}/v1/logs", timeout=5)))
    set_logger_provider(lp)
    _state["enabled"] = True
    _instruments.cache_clear()
    log.warning("관측 내보내기 활성 — %s → %s", service, endpoint or "memory")
    return True


def _emit(body: str, attributes: dict, ctx=None) -> None:
    """OTel Logs API 로 직접 기록 (SDK LoggingHandler 는 폐기 예정) — span 문맥을 붙여 추적과 연결한다."""
    from opentelemetry import _logs
    from opentelemetry import context as otel_context
    _logs.get_logger("aegismesh").emit(_logs.LogRecord(
        body=body, attributes=attributes, severity_text="INFO", severity_number=_logs.SeverityNumber.INFO,
        context=ctx or otel_context.get_current(), timestamp=time.time_ns()))


@lru_cache(maxsize=1)
def _instruments():
    m = metrics.get_meter("aegismesh")
    return {"requests": m.create_counter("aegis.gate.requests", unit="{request}", description="관문 판정 요청"),
            "duration": m.create_histogram("aegis.gate.duration", unit="ms", description="관문 합성 지연"),
            "degraded": m.create_counter("aegis.gate.degraded", unit="{agent}", description="강등된 에이전트 판정"),
            "findings": m.create_counter("aegis.findings", unit="{finding}", description="에이전트 판정")}


def record_gate(gate: str, tenant: str, trace_id: str, run: dict, decision: dict, extra: dict | None = None) -> None:
    """관문 판정 1건 → 루트 span + 에이전트 하위 span + 지표 + 비허용 판정 로그. 실패해도 판정 경로를 막지 않는다."""
    if not _state["enabled"]:
        return
    try:
        _record(gate, tenant, trace_id, run, decision, extra or {})
    except Exception:  # noqa: BLE001
        log.exception("관측 기록 실패")


def traced(trace_id: str, verdict: str, run: dict) -> bool:
    """추적 남길 판정인가 — 비허용·강등·예산 초과는 항상, allow 는 trace id 앞 8자리로 정한 비율만."""
    ratio = settings.otel_allow_trace_ratio
    if ratio >= 1 or verdict != "allow" or run["degraded"] or run.get("overBudget"):
        return True
    try:
        return int(trace_id[:8], 16) < ratio * 0x100000000
    except (TypeError, ValueError):
        return True


def _record(gate: str, tenant: str, trace_id: str, run: dict, decision: dict, extra: dict) -> None:
    ins = _instruments()
    eff = {d["findingId"]: d["effective"] for d in decision["decisions"] if d.get("findingId")}
    if not traced(trace_id, decision["verdict"], run):
        for f in run["findings"]:
            ins["findings"].add(1, {"aegis.agent.id": f.agent.id, "aegis.verdict": eff.get(f.id, f.verdict), "aegis.tenant": tenant})
        ins["requests"].add(1, {"aegis.gate": gate, "aegis.verdict": decision["verdict"], "aegis.tenant": tenant})
        ins["duration"].record(run["latencyMs"], {"aegis.gate": gate, "aegis.tenant": tenant})
        return
    tracer = trace.get_tracer("aegismesh")
    end = time.time_ns()
    start = end - int(run["latencyMs"] * 1_000_000)
    attrs = {"aegis.gate": gate, "aegis.tenant": tenant, "aegis.verdict": decision["verdict"],
             "aegis.agents.count": len(run["findings"]), "aegis.degraded.count": len(run["degraded"]),
             "aegis.over_budget": bool(run.get("overBudget")), "aegis.budget_ms": run.get("budgetMs") or 0}
    attrs.update({f"aegis.{k}": v for k, v in extra.items() if v is not None})
    token = _pending_trace.set(int(trace_id, 16) if trace_id and len(trace_id) == 32 else None)
    try:
        root = tracer.start_span(f"aegis.gate.{gate}", kind=SpanKind.INTERNAL, start_time=start, attributes=attrs,
                                 context=trace.set_span_in_context(trace.INVALID_SPAN))
    finally:
        _pending_trace.reset(token)
    ctx = trace.set_span_in_context(root)
    for f in run["findings"]:
        e = eff.get(f.id, f.verdict)
        s = tracer.start_span(f"aegis.agent.{f.agent.id}", context=ctx, start_time=start,
                              attributes={"aegis.agent.id": f.agent.id, "aegis.rule.id": f.rule_id, "aegis.verdict": f.verdict,
                                          "aegis.verdict.effective": e, "aegis.confidence": f.confidence,
                                          "aegis.severity": f.severity, "aegis.degraded": f.degraded,
                                          "aegis.finding.id": f.id})
        if f.degraded:
            s.set_status(Status(StatusCode.ERROR, "degraded"))
            ins["degraded"].add(1, {"aegis.gate": gate, "aegis.agent.id": f.agent.id})
        s.end(end_time=start + int(f.latency_ms * 1_000_000))
        ins["findings"].add(1, {"aegis.agent.id": f.agent.id, "aegis.verdict": e, "aegis.tenant": tenant})
        if e != "allow":
            _emit(f"finding {f.agent.id} {f.rule_id} {e}",
                  {"aegis.agent.id": f.agent.id, "aegis.rule.id": f.rule_id, "aegis.verdict": e, "aegis.tenant": tenant,
                   "aegis.gate": gate, "aegis.finding.id": f.id,
                   "aegis.evidence.locations": ",".join(ev.location or ev.kind for ev in f.evidence)[:200]}, ctx)
    root.end(end_time=end)
    ins["requests"].add(1, {"aegis.gate": gate, "aegis.verdict": decision["verdict"], "aegis.tenant": tenant})
    ins["duration"].record(run["latencyMs"], {"aegis.gate": gate, "aegis.tenant": tenant})


def test_log(text: str, by: str, tenant: str) -> str:
    """마스킹 규칙 시험 로그 (SCR-Q05) — 원문 그대로 수집기로 보내 수집 단계 치환을 확인한다. 반환 = trace id."""
    tracer = trace.get_tracer("aegismesh")
    with tracer.start_as_current_span("aegis.masking.test", attributes={"aegis.test.text": text, "aegis.by": by,
                                                                       "aegis.tenant": tenant}) as span:
        _emit(f"masking test: {text}", {"aegis.test.text": text, "aegis.by": by})
        return format(span.get_span_context().trace_id, "032x")


def enabled() -> bool:
    return _state["enabled"]


def flush() -> None:
    tp = trace.get_tracer_provider()
    if hasattr(tp, "force_flush"):
        tp.force_flush(5000)
    from opentelemetry._logs import get_logger_provider
    lp = get_logger_provider()
    if hasattr(lp, "force_flush"):
        lp.force_flush(5000)


# ── 마스킹 규칙 (수집기와 같은 원천) ─────────────────────────────
@lru_cache(maxsize=1)
def rules() -> list[dict]:
    rs = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    return [r | {"_re": re.compile(r["pattern"])} for r in rs]


def mask(text: str) -> tuple[str, list[str]]:
    hits = []
    for r in rules():
        text, n = r["_re"].subn(r["replacement"], text)
        if n:
            hits.append(r["name"])
    return text, hits


def status() -> dict:
    cfg = yaml.safe_load(COLLECTOR.read_text(encoding="utf-8"))
    pipes = cfg["service"]["pipelines"]
    return {"enabled": _state["enabled"], "service": _state["service"], "endpoint": settings.otel_endpoint or None,
            "protocol": "OTLP/HTTP (protobuf)", "signals": ["traces", "metrics", "logs"],
            "stats": {k: dict(v) for k, v in STATS.items()},
            "pipeline": {k: {"receivers": v["receivers"], "processors": v["processors"], "exporters": v["exporters"]}
                         for k, v in pipes.items()},
            "collector": {"image": "otel/opentelemetry-collector-contrib:0.162.0", "config": "infra/otel/collector.yaml",
                          "maskProcessor": "transform/mask", "statements": sum(len(s["statements"]) for k in
                                                                              ("trace_statements", "log_statements", "metric_statements")
                                                                              for s in cfg["processors"]["transform/mask"][k])},
            "masking": [{k: r[k] for k in ("name", "title", "pattern", "replacement")} for r in rules()],
            "payload": {"stored": False, "policy": "판정 원문·무해화 결과는 저장·전송하지 않는다(NFR-D1) — 관측에는 규칙·판정·위치만"}}
