"""
Shared gRPC server and channel factories.

Provides ``create_grpc_server`` and ``create_grpc_channel`` helpers that
wire up MMF-compatible observability (logging, metrics, correlation-id
propagation), health-checking, and optional TLS — so individual service
lifespans stay concise.
"""

from __future__ import annotations

import contextvars
import inspect
import logging
import os
import time
from typing import Any

import grpc
from grpc import aio as grpc_aio
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import HealthServicer
from grpc_reflection.v1alpha import reflection

logger = logging.getLogger(__name__)

# ContextVar for propagating correlation-id across gRPC call chains.
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)

# Environment names where insecure gRPC is permitted without explicit opt-in.
_DEV_ENVIRONMENTS = {"development", "dev", "local", "test"}


def _is_dev_environment() -> bool:
    """Return True when the service is running in a development-like environment."""
    return os.environ.get("ENVIRONMENT", "development").lower() in _DEV_ENVIRONMENTS


# ---------------------------------------------------------------------------
# Client-side interceptor: metrics for outbound gRPC calls
# ---------------------------------------------------------------------------


class MetricsClientInterceptor(grpc_aio.UnaryUnaryClientInterceptor):
    """Async client interceptor that records latency and status for
    outbound gRPC calls.  Pushes to Prometheus when available.
    """

    def __init__(self, service_name: str) -> None:
        self._service_name = service_name
        self._request_counter: Any = None
        self._latency_histogram: Any = None
        self._error_counter: Any = None
        try:
            from prometheus_client import Counter, Histogram

            self._request_counter = Counter(
                "grpc_client_requests_total",
                "Total outbound gRPC requests",
                ["source_service", "method", "status"],
            )
            self._latency_histogram = Histogram(
                "grpc_client_request_duration_seconds",
                "Outbound gRPC request duration",
                ["source_service", "method"],
                buckets=[
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ],
            )
            self._error_counter = Counter(
                "grpc_client_errors_total",
                "Total outbound gRPC errors",
                ["source_service", "method", "error_type"],
            )
        except Exception:
            logger.debug("prometheus_client not available; client metrics disabled")

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        method = client_call_details.method
        start = time.perf_counter()
        status = "OK"
        try:
            response = await continuation(client_call_details, request)
            return response
        except grpc.RpcError as exc:
            status = exc.code().name if hasattr(exc, "code") else "UNKNOWN"
            if self._error_counter:
                self._error_counter.labels(
                    source_service=self._service_name,
                    method=method,
                    error_type=status,
                ).inc()
            raise
        finally:
            duration = time.perf_counter() - start
            if self._request_counter:
                self._request_counter.labels(
                    source_service=self._service_name,
                    method=method,
                    status=status,
                ).inc()
            if self._latency_histogram:
                self._latency_histogram.labels(
                    source_service=self._service_name,
                    method=method,
                ).observe(duration)


class CorrelationIdClientInterceptor(grpc_aio.UnaryUnaryClientInterceptor):
    """Propagates ``x-correlation-id`` on outbound gRPC calls.

    Reads the current correlation-id from a ``contextvars.ContextVar``
    (set by the server-side ``CorrelationIdInterceptor`` or the
    ``RequestIdMiddleware``) and attaches it as metadata.
    """

    _HEADER = "x-correlation-id"

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        correlation_id = correlation_id_var.get("")

        if correlation_id:
            metadata = list(client_call_details.metadata or [])
            metadata.append((self._HEADER, correlation_id))
            client_call_details = client_call_details._replace(metadata=metadata)

        return await continuation(client_call_details, request)


class ServiceTokenClientInterceptor(grpc_aio.UnaryUnaryClientInterceptor):
    """Attaches ``x-service-token`` metadata on outbound gRPC calls
    so the receiving ``ServiceAuthInterceptor`` can authenticate them.
    """

    def __init__(self, token: str) -> None:
        self._token = token

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = list(client_call_details.metadata or [])
        metadata.append((_SERVICE_TOKEN_HEADER, self._token))
        client_call_details = client_call_details._replace(metadata=metadata)
        return await continuation(client_call_details, request)


# ---------------------------------------------------------------------------
# Server-side interceptor: structured logging + metrics
# ---------------------------------------------------------------------------


class LoggingMetricsInterceptor(grpc_aio.ServerInterceptor):
    """Async server interceptor that logs every RPC and records latency.

    Emits structured log lines at INFO (success) / WARNING (error) with
    method name, peer, status code, and duration.  Latency data is also
    pushed to Prometheus counters/histograms when a ``prometheus_client``
    ``CollectorRegistry`` is available.
    """

    def __init__(self, service_name: str) -> None:
        self._service_name = service_name
        self._request_counter: Any = None
        self._latency_histogram: Any = None
        self._error_counter: Any = None
        self._init_prometheus()

    def _init_prometheus(self) -> None:
        try:
            from prometheus_client import Counter, Histogram

            self._request_counter = Counter(
                "grpc_server_requests_total",
                "Total gRPC requests handled",
                ["service", "method", "status"],
            )
            self._latency_histogram = Histogram(
                "grpc_server_request_duration_seconds",
                "gRPC request duration",
                ["service", "method"],
                buckets=[
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ],
            )
            self._error_counter = Counter(
                "grpc_server_errors_total",
                "Total gRPC errors",
                ["service", "method", "error_type"],
            )
        except Exception:
            logger.debug("prometheus_client not available; server metrics disabled")

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler

        method = handler_call_details.method

        # Wrap unary-unary and unary-stream handlers
        if handler.unary_unary:
            original = handler.unary_unary

            async def _wrapped_unary(request, context):
                return await self._traced_call(method, original, request, context)

            return grpc.unary_unary_rpc_method_handler(
                _wrapped_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler

    async def _traced_call(self, method, handler, request, context):
        peer = context.peer() if hasattr(context, "peer") else "unknown"
        start = time.perf_counter()
        status = "OK"
        try:
            result = handler(request, context)
            if inspect.isawaitable(result):
                result = await result
            return result
        except Exception as exc:
            status = type(exc).__name__
            if self._error_counter:
                self._error_counter.labels(
                    service=self._service_name,
                    method=method,
                    error_type=status,
                ).inc()
            logger.warning(
                "gRPC %s failed peer=%s error=%s",
                method, peer, exc,
            )
            raise
        finally:
            duration = time.perf_counter() - start
            if self._request_counter:
                self._request_counter.labels(
                    service=self._service_name,
                    method=method,
                    status=status,
                ).inc()
            if self._latency_histogram:
                self._latency_histogram.labels(
                    service=self._service_name,
                    method=method,
                ).observe(duration)
            if status == "OK":
                logger.info(
                    "gRPC %s peer=%s status=OK duration=%.3fs",
                    method, peer, duration,
                )


# ---------------------------------------------------------------------------
# Server-side interceptor: correlation-id propagation
# ---------------------------------------------------------------------------


class CorrelationIdInterceptor(grpc_aio.ServerInterceptor):
    """Extracts ``x-correlation-id`` from inbound metadata and makes it
    available via ``contextvars`` and as trailing metadata.

    Compatible with MMF's ``StandardCorrelationInterceptor`` header names.
    """

    _HEADER = "x-correlation-id"

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None or not handler.unary_unary:
            return handler

        original = handler.unary_unary

        async def _wrapped(request, context):
            cid = ""
            metadata = dict(context.invocation_metadata()) if hasattr(context, "invocation_metadata") else {}
            cid = metadata.get(self._HEADER, "")
            if cid:
                correlation_id_var.set(cid)
                context.set_trailing_metadata(
                    [(self._HEADER, cid)]
                )
            result = original(request, context)
            if inspect.isawaitable(result):
                result = await result
            return result

        return grpc.unary_unary_rpc_method_handler(
            _wrapped,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


# ---------------------------------------------------------------------------
# Service authentication interceptor
# ---------------------------------------------------------------------------

_SERVICE_TOKEN_HEADER = "x-service-token"


class ServiceAuthInterceptor(grpc_aio.ServerInterceptor):
    """Validates a shared service token on inbound gRPC calls.

    Enabled when ``GRPC_SERVICE_TOKEN`` is set.  Health-check and
    reflection RPCs are exempt so that probes still work without tokens.
    """

    _EXEMPT_PREFIXES = (
        "/grpc.health.",
        "/grpc.reflection.",
    )

    def __init__(self, expected_token: str) -> None:
        import hmac as _hmac

        self._expected_token = expected_token
        self._hmac = _hmac

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method or ""
        if any(method.startswith(p) for p in self._EXEMPT_PREFIXES):
            return await continuation(handler_call_details)

        metadata = dict(handler_call_details.invocation_metadata)
        token = metadata.get(_SERVICE_TOKEN_HEADER, "")

        if not self._hmac.compare_digest(token, self._expected_token):
            logger.warning(
                "Rejected unauthenticated gRPC call to %s", method
            )

            async def _abort(request, context):
                await context.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "Missing or invalid service token",
                )

            return grpc.unary_unary_rpc_method_handler(_abort)

        return await continuation(handler_call_details)


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------


def _read_file_bytes(path: str | None) -> bytes | None:
    """Read a file as bytes, returning None if path is empty."""
    if not path:
        return None
    with open(path, "rb") as fh:
        return fh.read()


def _build_server_credentials() -> grpc.ServerCredentials | None:
    """Build TLS server credentials from environment variables.

    Env vars:
        GRPC_TLS_CERT      — path to server certificate PEM
        GRPC_TLS_KEY       — path to server private key PEM
        GRPC_TLS_CA_CERT   — path to CA certificate for client verification
        GRPC_TLS_REQUIRE_CLIENT_AUTH — set to "true" for mTLS
    """
    cert_path = os.environ.get("GRPC_TLS_CERT", "")
    key_path = os.environ.get("GRPC_TLS_KEY", "")
    if not cert_path or not key_path:
        return None

    cert = _read_file_bytes(cert_path)
    key = _read_file_bytes(key_path)
    ca_cert = _read_file_bytes(os.environ.get("GRPC_TLS_CA_CERT", ""))
    require_client_auth = os.environ.get(
        "GRPC_TLS_REQUIRE_CLIENT_AUTH", ""
    ).lower() in ("true", "1", "yes")

    return grpc.ssl_server_credentials(
        [(key, cert)],
        root_certificates=ca_cert,
        require_client_auth=require_client_auth,
    )


def _build_channel_credentials() -> grpc.ChannelCredentials | None:
    """Build TLS channel credentials from environment variables.

    Env vars:
        GRPC_TLS_CA_CERT       — path to CA cert for server verification
        GRPC_TLS_CLIENT_CERT   — path to client certificate PEM (mTLS)
        GRPC_TLS_CLIENT_KEY    — path to client private key PEM (mTLS)
    """
    ca_cert = _read_file_bytes(os.environ.get("GRPC_TLS_CA_CERT", ""))
    if not ca_cert:
        return None

    client_cert = _read_file_bytes(os.environ.get("GRPC_TLS_CLIENT_CERT", ""))
    client_key = _read_file_bytes(os.environ.get("GRPC_TLS_CLIENT_KEY", ""))

    return grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=client_key,
        certificate_chain=client_cert,
    )


# ---------------------------------------------------------------------------
# Public API — server factory
# ---------------------------------------------------------------------------


def create_grpc_server(
    service_name: str,
    *,
    interceptors: list[grpc_aio.ServerInterceptor] | None = None,
) -> tuple[grpc_aio.Server, HealthServicer]:
    """Create a gRPC async server with observability wired in.

    Returns ``(server, health_servicer)`` so callers can register their
    own servicers and then call ``await server.start()``.

    Built-in features:
    - ``LoggingMetricsInterceptor`` — structured logging + Prometheus
    - ``CorrelationIdInterceptor`` — correlation-id propagation
    - gRPC health checking (``grpc.health.v1.Health``)
    - gRPC server reflection

    Parameters
    ----------
    service_name:
        Logical name shown in logs / metrics labels.
    interceptors:
        Additional interceptors prepended to the chain.
    """
    all_interceptors: list[grpc_aio.ServerInterceptor] = [
        CorrelationIdInterceptor(),
        LoggingMetricsInterceptor(service_name),
    ]

    # Service-to-service authentication when GRPC_SERVICE_TOKEN is set.
    service_token = os.environ.get("GRPC_SERVICE_TOKEN", "")
    if service_token:
        all_interceptors.insert(0, ServiceAuthInterceptor(service_token))
    elif not _is_dev_environment():
        logger.warning(
            "GRPC_SERVICE_TOKEN is not set in a non-dev environment — "
            "inter-service gRPC calls are unauthenticated"
        )

    if interceptors:
        all_interceptors = list(interceptors) + all_interceptors

    server = grpc_aio.server(interceptors=all_interceptors)

    # Health checking
    health_servicer = HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    return server, health_servicer


def start_grpc_server_port(
    server: grpc_aio.Server,
    port: int,
    *,
    service_names: list[str] | None = None,
    health_servicer: HealthServicer | None = None,
) -> None:
    """Bind *server* to *port* (TLS-aware) and enable reflection.

    If ``GRPC_TLS_CERT`` / ``GRPC_TLS_KEY`` are set, the server binds
    a secure port; otherwise an insecure port.  Outside development
    environments, insecure binding is rejected unless
    ``GRPC_INSECURE_ALLOWED=true`` is explicitly set.

    ``service_names`` are registered with gRPC server reflection so
    that tools like ``grpcurl`` can introspect the API.
    """
    credentials = _build_server_credentials()
    addr = f"[::]:{port}"

    if credentials:
        server.add_secure_port(addr, credentials)
        logger.info("gRPC server bound to %s (TLS enabled)", addr)
    else:
        insecure_allowed = (
            _is_dev_environment()
            or os.environ.get("GRPC_INSECURE_ALLOWED", "").lower()
            in ("true", "1", "yes")
        )
        if not insecure_allowed:
            raise RuntimeError(
                f"Refusing to start gRPC server on {addr} without TLS in "
                f"a non-dev environment. Set GRPC_TLS_CERT/GRPC_TLS_KEY "
                f"or GRPC_INSECURE_ALLOWED=true to override."
            )
        server.add_insecure_port(addr)
        logger.warning("gRPC server bound to %s (insecure — dev mode)", addr)

    # Reflection
    reflection_names = list(service_names or [])
    reflection_names.append(reflection.SERVICE_NAME)
    if health_servicer:
        reflection_names.append("grpc.health.v1.Health")
    reflection.enable_server_reflection(reflection_names, server)

    # Mark all services as SERVING
    if health_servicer:
        for svc in (service_names or []):
            health_servicer.set(svc, health_pb2.HealthCheckResponse.SERVING)
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)


# ---------------------------------------------------------------------------
# Public API — channel factory
# ---------------------------------------------------------------------------


def create_grpc_channel(
    target: str,
    *,
    service_name: str | None = None,
    interceptors: list[grpc_aio.ClientInterceptor] | None = None,
) -> grpc_aio.Channel:
    """Create a gRPC async channel with keepalive and optional TLS.

    If ``GRPC_TLS_CA_CERT`` is set, a secure channel is created;
    otherwise an insecure one.  Outside development environments,
    insecure channels are rejected unless ``GRPC_INSECURE_ALLOWED=true``.

    When ``GRPC_SERVICE_TOKEN`` is set the token is automatically
    attached as ``x-service-token`` call metadata via a client
    interceptor so that the receiving server can authenticate the call.

    Built-in client interceptors (when *service_name* is provided):
    - ``MetricsClientInterceptor`` — call count + latency Prometheus
    - ``CorrelationIdClientInterceptor`` — propagate correlation-id

    Parameters
    ----------
    target:
        Address string (e.g. ``"auth:9001"``).
    service_name:
        Calling service name for metrics labels.  When *None* the
        built-in client interceptors are skipped.
    interceptors:
        Additional client-side interceptors appended after the defaults.
    """
    all_interceptors: list[grpc_aio.ClientInterceptor] = []
    if service_name:
        all_interceptors.append(CorrelationIdClientInterceptor())
        all_interceptors.append(MetricsClientInterceptor(service_name))

    # Attach service token for inter-service authentication.
    service_token = os.environ.get("GRPC_SERVICE_TOKEN", "")
    if service_token:
        all_interceptors.append(ServiceTokenClientInterceptor(service_token))

    if interceptors:
        all_interceptors.extend(interceptors)

    options = [
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 5_000),
        ("grpc.keepalive_permit_without_calls", True),
        ("grpc.http2.max_pings_without_data", 0),
    ]

    credentials = _build_channel_credentials()
    if credentials:
        channel = grpc_aio.secure_channel(
            target, credentials, options=options,
            interceptors=all_interceptors or None,
        )
        logger.info("gRPC channel to %s (TLS enabled)", target)
    else:
        insecure_allowed = (
            _is_dev_environment()
            or os.environ.get("GRPC_INSECURE_ALLOWED", "").lower()
            in ("true", "1", "yes")
        )
        if not insecure_allowed:
            raise RuntimeError(
                f"Refusing to open insecure gRPC channel to {target} in "
                f"a non-dev environment. Set GRPC_TLS_CA_CERT or "
                f"GRPC_INSECURE_ALLOWED=true to override."
            )
        channel = grpc_aio.insecure_channel(
            target, options=options,
            interceptors=all_interceptors or None,
        )
        logger.warning("gRPC channel to %s (insecure — dev mode)", target)
    return channel
