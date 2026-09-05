"""Phase 17 -- observability.

Two independent pieces, both following the same offline-safety discipline
as the rest of the codebase (app/ai/classifier.py, services/collectors/*):

  1. Tracing: uses the `opentelemetry` SDK if installed and
     OTEL_ENABLED=true, exporting spans via OTLP (OTEL_EXPORTER_OTLP_ENDPOINT)
     for HTTP request handling, the pipeline, AI inference, parsing, OPA,
     Batfish, risk, NATS, device collection, OpenBao, MinIO, and Fabric
     (problem statement Phase 17 list). `start_span()` is a no-op context
     manager when the SDK isn't installed or OTEL_ENABLED=false, so nothing
     importing this module needs its own try/except.

  2. Metrics: a small in-process counter/histogram registry, independent of
     the OpenTelemetry SDK, exposed at GET /api/metrics in Prometheus text
     exposition format -- the format VictoriaMetrics scrapes directly, so
     no extra exporter dependency is required to satisfy "expose metrics
     suitable for VictoriaMetrics/Grafana". Covers exactly the metric names
     listed in the problem statement: scan_duration_ms, ai_inference_
     duration_ms, ai_review_rate, unknown_rate, opa_failure_count,
     batfish_failure_count, batfish_unsupported_count,
     collection_success_rate, collection_failure_count, drift_count,
     fabric_anchor_success_count, fabric_anchor_failure_count.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Dict, Iterator, Optional

logger = logging.getLogger("observability")

OTEL_ENABLED = os.getenv("OTEL_ENABLED", "false").strip().lower() == "true"
OTEL_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "netsec-auditor-backend")
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

_tracer = None
_tracing_initialized = False


def setup_tracing() -> None:
    """Call once at application startup (see main.py lifespan). Safe to
    call even when OTEL_ENABLED=false or the SDK isn't installed -- both
    just leave `_tracer` as None, and start_span() degrades to a no-op."""
    global _tracer, _tracing_initialized
    if _tracing_initialized:
        return
    _tracing_initialized = True

    if not OTEL_ENABLED:
        logger.info("OpenTelemetry tracing disabled (OTEL_ENABLED=false)")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        resource = Resource(attributes={SERVICE_NAME: OTEL_SERVICE_NAME})
        provider = TracerProvider(resource=resource)
        if OTEL_EXPORTER_OTLP_ENDPOINT:
            exporter = OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(OTEL_SERVICE_NAME)
        logger.info("OpenTelemetry tracing enabled (endpoint=%s)", OTEL_EXPORTER_OTLP_ENDPOINT or "none configured")
    except ImportError:
        logger.warning("OTEL_ENABLED=true but the opentelemetry SDK is not installed; tracing stays disabled")
        _tracer = None
    except Exception:  # noqa: BLE001 -- tracing setup must never crash the app
        logger.warning("Failed to initialize OpenTelemetry tracing", exc_info=True)
        _tracer = None


@contextmanager
def start_span(name: str, **attributes) -> Iterator[None]:
    """No-op unless setup_tracing() successfully initialized a tracer.
    Usage: `with start_span("pipeline.opa_evaluate", scan_id=scan.id): ...`"""
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as span:
        for key, value in attributes.items():
            try:
                span.set_attribute(key, value)
            except Exception:  # noqa: BLE001 -- a bad attribute value must never break the call it wraps
                pass
        yield


def instrument_fastapi(app) -> None:
    """Best-effort auto-instrumentation of every HTTP route. No-op if the
    SDK/instrumentation package isn't installed or tracing is disabled."""
    if not OTEL_ENABLED or _tracer is None:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        logger.warning("opentelemetry-instrumentation-fastapi not installed; HTTP spans unavailable")
    except Exception:  # noqa: BLE001
        logger.warning("Failed to instrument FastAPI for tracing", exc_info=True)


# ---------------------------------------------------------------------------
# Metrics -- independent of the tracing SDK, always active (no optional
# dependency), thread-safe, process-local (each API worker exposes its own
# /api/metrics; that's the standard Prometheus/VictoriaMetrics scrape model
# for a horizontally-scaled service).
# ---------------------------------------------------------------------------

class _Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._histogram_sums: Dict[str, float] = {}
        self._histogram_counts: Dict[str, int] = {}

    def inc_counter(self, name: str, value: float = 1.0) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + value

    def observe(self, name: str, value_ms: float) -> None:
        """Records one observation for a duration-style metric, tracked as
        a running sum+count so /api/metrics can expose both the average and
        the total count -- deliberately simple rather than true histogram
        buckets, which VictoriaMetrics/Grafana can still graph via rate()
        and the _sum/_count convention."""
        with self._lock:
            self._histogram_sums[name] = self._histogram_sums.get(name, 0.0) + value_ms
            self._histogram_counts[name] = self._histogram_counts.get(name, 0) + 1

    def set_ratio(self, name: str, numerator: int, denominator: int) -> None:
        with self._lock:
            self._counters[f"{name}_ratio"] = (numerator / denominator) if denominator else 0.0

    def render_prometheus(self) -> str:
        lines = []
        with self._lock:
            for name, value in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name} {value}")
            for name in sorted(self._histogram_sums):
                lines.append(f"# TYPE {name} summary")
                lines.append(f"{name}_sum {self._histogram_sums[name]}")
                lines.append(f"{name}_count {self._histogram_counts.get(name, 0)}")
        return "\n".join(lines) + "\n"


registry = _Registry()


@contextmanager
def timed_metric(name: str) -> Iterator[None]:
    """Records `name` (an _ms duration metric) for the wrapped block, in
    addition to whatever tracing span the caller may also open."""
    start = time.perf_counter()
    try:
        yield
    finally:
        registry.observe(name, (time.perf_counter() - start) * 1000.0)


# Convenience wrappers for the specific counters named in the problem
# statement, so call sites read as intent rather than raw metric names.

def record_scan_duration_ms(value_ms: float) -> None:
    registry.observe("scan_duration_ms", value_ms)


def record_ai_inference_duration_ms(value_ms: float) -> None:
    registry.observe("ai_inference_duration_ms", value_ms)


def record_ai_decision(requires_review: bool, is_unknown: bool) -> None:
    registry.inc_counter("ai_decision_total")
    if requires_review:
        registry.inc_counter("ai_review_total")
    if is_unknown:
        registry.inc_counter("ai_unknown_total")
    with registry._lock:
        total = registry._counters.get("ai_decision_total", 0.0)
        review_total = registry._counters.get("ai_review_total", 0.0)
        unknown_total = registry._counters.get("ai_unknown_total", 0.0)
        registry._counters["ai_review_rate"] = (review_total / total) if total else 0.0
        registry._counters["unknown_rate"] = (unknown_total / total) if total else 0.0


def record_opa_failure() -> None:
    registry.inc_counter("opa_failure_count")


def record_batfish_failure() -> None:
    registry.inc_counter("batfish_failure_count")


def record_batfish_unsupported() -> None:
    registry.inc_counter("batfish_unsupported_count")


def record_collection_result(success: bool) -> None:
    registry.inc_counter("collection_attempt_total")
    if success:
        registry.inc_counter("collection_success_total")
    else:
        registry.inc_counter("collection_failure_count")
    with registry._lock:
        attempts = registry._counters.get("collection_attempt_total", 0.0)
        successes = registry._counters.get("collection_success_total", 0.0)
        registry._counters["collection_success_rate"] = (successes / attempts) if attempts else 0.0


def record_drift_event() -> None:
    registry.inc_counter("drift_count")


def record_fabric_anchor_result(success: bool) -> None:
    if success:
        registry.inc_counter("fabric_anchor_success_count")
    else:
        registry.inc_counter("fabric_anchor_failure_count")


def record_gnmi_set_result(success: bool) -> None:
    registry.inc_counter("gnmi_set_success_count" if success else "gnmi_set_failure_count")


def record_gnmi_verification_failure() -> None:
    registry.inc_counter("gnmi_verification_failure_count")


def record_pyats_verification_result(success: bool) -> None:
    registry.inc_counter("pyats_verification_success_count" if success else "pyats_verification_failure_count")