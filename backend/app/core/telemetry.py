import logging
import re
import threading
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult

from app.core.config import get_settings

logger = logging.getLogger("sentinelgraph.telemetry")

_METRIC_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_]")


class HttpOtlpJsonSpanExporter(SpanExporter):
    """Lightweight OTLP/HTTP JSON trace exporter (v1/traces) using httpx."""

    def __init__(self, endpoint: str, timeout: float = 2.0) -> None:
        cleaned = endpoint.rstrip("/")
        if not cleaned.endswith("/v1/traces"):
            cleaned = f"{cleaned}/v1/traces"
        self.endpoint = cleaned
        self.timeout = timeout
        self._shutdown = False

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self._shutdown or not spans:
            return SpanExportResult.SUCCESS
        span_records: list[dict[str, Any]] = []
        service_name = get_settings().otel_service_name
        for sp in spans:
            ctx = sp.get_span_context()
            attrs = [
                {"key": str(k), "value": {"stringValue": str(v)}}
                for k, v in (sp.attributes or {}).items()
            ]
            span_records.append(
                {
                    "traceId": f"{ctx.trace_id:032x}" if ctx else "",
                    "spanId": f"{ctx.span_id:016x}" if ctx else "",
                    "name": sp.name,
                    "startTimeUnixNano": str(sp.start_time or 0),
                    "endTimeUnixNano": str(sp.end_time or 0),
                    "attributes": attrs,
                }
            )
        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": service_name}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "sentinelgraph"},
                            "spans": span_records,
                        }
                    ],
                }
            ]
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    self.endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code >= 400:
                    return SpanExportResult.FAILURE
            return SpanExportResult.SUCCESS
        except Exception:
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        self._shutdown = True

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def configure_telemetry() -> trace.Tracer:
    settings = get_settings()
    resource = Resource.create({"service.name": settings.otel_service_name})
    provider = TracerProvider(resource=resource)
    if settings.otel_exporter_otlp_endpoint:
        try:
            exporter = HttpOtlpJsonSpanExporter(settings.otel_exporter_otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except Exception as exc:
            logger.warning("Failed to initialize OTLP HTTP exporter: %s", exc)
    trace.set_tracer_provider(provider)
    return trace.get_tracer("sentinelgraph")


@dataclass
class MetricsRegistry:
    """Thread-safe observability metrics store (never stores sensitive asset names in labels)."""

    _lock: threading.Lock = field(default_factory=threading.Lock)
    counters: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    latencies_ms: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    gauges: dict[str, float] = field(default_factory=dict)

    def inc(self, metric_name: str, amount: int = 1) -> None:
        with self._lock:
            self.counters[metric_name] += amount

    def observe_ms(self, metric_name: str, value_ms: float) -> None:
        with self._lock:
            samples = self.latencies_ms[metric_name]
            samples.append(round(value_ms, 3))
            if len(samples) > 500:
                del samples[: len(samples) - 500]

    def set_gauge(self, metric_name: str, value: float) -> None:
        with self._lock:
            self.gauges[metric_name] = value

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            latency_summary: dict[str, dict[str, float]] = {}
            for name, vals in self.latencies_ms.items():
                if not vals:
                    continue
                ordered = sorted(vals)
                p95_idx = min(len(ordered) - 1, int(len(ordered) * 0.95))
                latency_summary[name] = {
                    "count": float(len(ordered)),
                    "avg_ms": round(sum(ordered) / len(ordered), 2),
                    "p95_ms": ordered[p95_idx],
                    "max_ms": ordered[-1],
                }
            return {
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "latencies": latency_summary,
                "collected_at_epoch": time.time(),
            }

    def to_prometheus_text(self) -> str:
        snap = self.snapshot()
        lines: list[str] = []
        counters: dict[str, int] = snap["counters"]  # type: ignore[assignment]
        gauges: dict[str, float] = snap["gauges"]  # type: ignore[assignment]
        latencies: dict[str, dict[str, float]] = snap["latencies"]  # type: ignore[assignment]

        for name, value in sorted(counters.items()):
            safe = f"sentinelgraph_counter_{_METRIC_SANITIZE_RE.sub('_', name)}"
            lines.append(f"# TYPE {safe} counter")
            lines.append(f"{safe} {int(value)}")

        for name, value in sorted(gauges.items()):
            safe = f"sentinelgraph_gauge_{_METRIC_SANITIZE_RE.sub('_', name)}"
            lines.append(f"# TYPE {safe} gauge")
            lines.append(f"{safe} {float(value)}")

        for name, stats in sorted(latencies.items()):
            safe = f"sentinelgraph_latency_ms_{_METRIC_SANITIZE_RE.sub('_', name)}"
            lines.append(f"# TYPE {safe} summary")
            lines.append(f'{safe}{{quantile="0.95"}} {stats["p95_ms"]}')
            lines.append(f"{safe}_sum {round(stats['avg_ms'] * stats['count'], 3)}")
            lines.append(f"{safe}_count {int(stats['count'])}")

        return "\n".join(lines) + ("\n" if lines else "")


metrics = MetricsRegistry()
tracer = configure_telemetry()
