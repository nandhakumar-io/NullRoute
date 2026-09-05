"""
Phase 17 -- Observability (OpenTelemetry).

Same optional-dependency pattern used throughout this codebase (AI models,
collectors, deployers): if the `opentelemetry-*` packages aren't installed,
or OTEL_ENABLED=false, every function here degrades to a harmless no-op
rather than raising at import time, so the rest of the backend stays
importable/testable without them (RULE: prefer additive changes).

Usage:
    from app.services.telemetry import tracer, record_histogram, increment_counter

    with tracer.start_as_current_span("pipeline.run"):
        ...
    record_histogram("scan_duration_ms", elapsed_ms, {"framework": framework})
    increment_counter("opa_failure_count", {"scan_id": scan_id})

Metrics exposed (per problem statement Phase 17), all counters unless noted:
    scan_duration_ms (histogram), ai_inference_duration_ms (histogram),
    ai_review_rate (counter: increments once per AI analysis with an
        attribute requires_review=true/false -- compute the *rate* in
        Grafana as requires_review-true / total, never fabricated here),
    unknown_rate (counter: same pattern, attribute decision=UNKNOWN),
    opa_failure_count, batfish_failure_count, batfish_unsupported_count,
    collection_success_rate (counter, attribute success=true/false --
        rate computed in Grafana), collection_failure_count, drift_count,
    fabric_anchor_success_count, fabric_anchor_failure_count.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, Optional

logger = logging.getLogger("telemetry")

OTEL_ENABLED = os.getenv("OTEL_ENABLED", "false").strip().lower() == "true"
OTEL_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "netsecauditor-backend")
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

_tracer = None
_meter = None
_instruments: Dict[str, Any] = {}
_available = False

_COUNTER_NAMES = {
    "ai_review_rate", "unknown_rate", "opa_failure_count", "batfish_failure_count",
    "batfish_unsupported_count", "collection_success_rate", "collection_failure_count",
    "drift_count", "fabric_anchor_success_count", "fabric_anchor_failure_count",
}
_HISTOGRAM_NAMES = {"scan_duration_ms", "ai_inference_duration_ms"}

if OTEL_ENABLED:
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import \
            OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import \
            OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        _resource = Resource.create({"service.name": OTEL_SERVICE_NAME})

        _trace_provider = TracerProvider(resource=_resource)
        _trace_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True)))
        trace.set_tracer_provider(_trace_provider)
        _tracer = trace.get_tracer(OTEL_SERVICE_NAME)

        _metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True))
        _meter_provider = MeterProvider(resource=_resource, metric_readers=[_metric_reader])
        metrics.set_meter_provider(_meter_provider)
        _meter = metrics.get_meter(OTEL_SERVICE_NAME)

        for name in _COUNTER_NAMES:
            _instruments[name] = _meter.create_counter(name)
        for name in _HISTOGRAM_NAMES:
            _instruments[name] = _meter.create_histogram(name, unit="ms")

        _available = True
        logger.info("OpenTelemetry enabled: service=%s endpoint=%s", OTEL_SERVICE_NAME, OTEL_EXPORTER_OTLP_ENDPOINT)
    except Exception:  # noqa: BLE001 -- an OTel/collector outage must never break the app
        logger.warning("OTEL_ENABLED=true but OpenTelemetry setup failed; continuing uninstrumented", exc_info=True)
        _tracer = None
        _meter = None
        _available = False


class _NoOpSpan:
    def set_attribute(self, *a, **k):
        pass

    def record_exception(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _NoOpTracer:
    @contextmanager
    def start_as_current_span(self, name: str, **kwargs):
        yield _NoOpSpan()


tracer = _tracer if _available else _NoOpTracer()


def instrument_app(app) -> None:
    """Call once, after the FastAPI app object is constructed, to add
    automatic HTTP server spans. No-op if OTel isn't enabled/installed."""
    if not _available:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
    except Exception:  # noqa: BLE001
        logger.warning("FastAPI OTel auto-instrumentation failed", exc_info=True)


def record_histogram(name: str, value: float, attributes: Optional[Dict[str, Any]] = None) -> None:
    if not _available or name not in _instruments:
        return
    try:
        _instruments[name].record(value, attributes or {})
    except Exception:  # noqa: BLE001 -- metrics must never break request handling
        logger.debug("Failed to record histogram %s", name, exc_info=True)


def increment_counter(name: str, attributes: Optional[Dict[str, Any]] = None, value: int = 1) -> None:
    if not _available or name not in _instruments:
        return
    try:
        _instruments[name].add(value, attributes or {})
    except Exception:  # noqa: BLE001
        logger.debug("Failed to increment counter %s", name, exc_info=True)