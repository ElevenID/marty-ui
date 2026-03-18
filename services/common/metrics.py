"""
Prometheus metrics endpoint and OpenTelemetry gRPC instrumentation.

Usage in any service's ``create_app()``::

    from common.metrics import mount_metrics

    app = FastAPI(...)
    mount_metrics(app)

For OpenTelemetry tracing, call once during startup::

    from common.metrics import init_otel_tracing
    init_otel_tracing("auth")
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Response

logger = logging.getLogger(__name__)


def mount_metrics(app: FastAPI) -> None:
    """Add a ``/metrics`` endpoint that exposes Prometheus metrics.

    Relies on ``prometheus_client`` already being imported by
    :class:`~common.grpc_factory.LoggingMetricsInterceptor`, which
    registers ``grpc_server_*`` counters/histograms in the default
    collector registry.
    """
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:
        logger.debug("prometheus_client not installed; /metrics endpoint disabled")
        return

    @app.get("/metrics", include_in_schema=False)
    async def _metrics() -> Response:
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )


def init_otel_tracing(service_name: str) -> None:
    """Bootstrap OpenTelemetry tracing with OTLP gRPC export.

    Sends traces to the OTLP endpoint configured via
    ``OTEL_EXPORTER_OTLP_ENDPOINT`` (default ``jaeger:4317``).
    Automatically instruments gRPC client and server calls when
    ``opentelemetry-instrumentation-grpc`` is installed.

    Safe to call even when the OTel packages are missing — it simply
    logs a debug message and returns.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError:
        logger.debug("opentelemetry SDK not installed; tracing disabled")
        return

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "jaeger:4317")

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=endpoint, insecure=True)
        )
    )
    trace.set_tracer_provider(provider)

    # Auto-instrument grpc if the instrumentation package is available
    try:
        from opentelemetry.instrumentation.grpc import (
            GrpcInstrumentorClient,
            GrpcInstrumentorServer,
        )
        GrpcInstrumentorServer().instrument()
        GrpcInstrumentorClient().instrument()
        logger.info("OpenTelemetry gRPC instrumentation enabled for %s", service_name)
    except ImportError:
        logger.debug("opentelemetry-instrumentation-grpc not installed; gRPC auto-instrumentation skipped")

    logger.info("OpenTelemetry tracing initialised → %s", endpoint)
