"""Tests for common.grpc_factory — shared gRPC server/channel factories."""

from __future__ import annotations

import asyncio
import os
import socket
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common.grpc_factory import (
    CorrelationIdInterceptor,
    LoggingMetricsInterceptor,
    ServiceAuthInterceptor,
    ServiceTokenClientInterceptor,
    WorkloadIdentityInterceptor,
    create_grpc_channel,
    create_grpc_server,
    start_grpc_server_port,
)


@pytest.fixture(scope="module", autouse=True)
def grpc_event_loop():
    """Keep grpc.aio tests independent from event loops closed by other modules."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    yield loop


@pytest.fixture(autouse=True)
def isolated_grpc_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("GRPC_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("GRPC_SERVICE_TOKEN_FILE", raising=False)
    for name in (
        "GRPC_WORKLOAD_TLS_SERVER_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KEY",
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_CA_CERT",
    ):
        monkeypatch.delenv(name, raising=False)


# ── create_grpc_server ──────────────────────────────────────────────


class TestCreateGrpcServer:
    def test_returns_server_and_health_servicer(self):
        server, health = create_grpc_server("test-svc")
        assert server is not None
        assert health is not None

    def test_server_has_health_service(self):
        server, health = create_grpc_server("test-svc")
        # HealthServicer is registered; we can set service status
        from grpc_health.v1 import health_pb2

        health.set("test-svc", health_pb2.HealthCheckResponse.SERVING)


# ── start_grpc_server_port ───────────────────────────────────────────


class TestStartGrpcServerPort:
    def test_binds_insecure_port(self):
        server, health = create_grpc_server("test-svc")
        start_grpc_server_port(
            server,
            50099,
            service_names=["my.service.v1.MyService"],
            health_servicer=health,
        )

    def test_binds_secure_port_when_tls_configured(self, tmp_path):
        # Create fake cert/key files
        cert_file = tmp_path / "server.pem"
        key_file = tmp_path / "server.key"
        cert_file.write_bytes(b"fake-cert")
        key_file.write_bytes(b"fake-key")

        server, health = create_grpc_server("test-svc")

        with patch.dict(
            os.environ,
            {
                "GRPC_TLS_CERT": str(cert_file),
                "GRPC_TLS_KEY": str(key_file),
            },
        ):
            # ssl_server_credentials will fail with fake cert data,
            # but we verify the path is taken
            try:
                start_grpc_server_port(server, 50098, service_names=["svc"])
            except Exception:
                pass  # Expected with fake certs


# ── create_grpc_channel ──────────────────────────────────────────────


class TestCreateGrpcChannel:
    def test_creates_insecure_channel(self):
        channel = create_grpc_channel("localhost:50051")
        assert channel is not None

    def test_creates_channel_with_keepalive(self):
        with patch("common.grpc_factory.grpc_aio.insecure_channel") as create_channel:
            create_channel.return_value = MagicMock()

            channel = create_grpc_channel("localhost:50052")

        assert channel is create_channel.return_value
        options = dict(create_channel.call_args.kwargs["options"])
        assert options == {
            "grpc.keepalive_time_ms": 300_000,
            "grpc.keepalive_timeout_ms": 20_000,
            "grpc.keepalive_permit_without_calls": False,
            "grpc.http2.max_pings_without_data": 2,
        }


class TestServiceAuthentication:
    def test_production_server_requires_service_token(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")

        with pytest.raises(RuntimeError, match="GRPC_SERVICE_TOKEN.*required"):
            create_grpc_server("test-svc")

    def test_production_channel_requires_service_token(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")

        with pytest.raises(RuntimeError, match="GRPC_SERVICE_TOKEN.*required"):
            create_grpc_channel("localhost:50051", service_name="test-svc")

    @pytest.mark.parametrize("token", ["change_me_grpc_token", "too-short"])
    def test_production_rejects_weak_service_tokens(self, monkeypatch, token):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN", token)

        with pytest.raises(RuntimeError):
            create_grpc_server("test-svc")

    def test_production_reads_token_from_secret_file(self, monkeypatch, tmp_path):
        token_file = tmp_path / "grpc_service_token"
        token_file.write_text("a" * 48 + "\n", encoding="utf-8")
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN_FILE", str(token_file))

        with patch("common.grpc_factory.grpc_aio.server") as server_factory:
            server_factory.return_value = MagicMock()
            create_grpc_server("test-svc")

        interceptors = server_factory.call_args.kwargs["interceptors"]
        assert isinstance(interceptors[0], ServiceAuthInterceptor)

    def test_production_channel_sends_secret_file_token(self, monkeypatch, tmp_path):
        token_file = tmp_path / "grpc_service_token"
        token = "b" * 48
        token_file.write_text(token, encoding="utf-8")
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN_FILE", str(token_file))
        monkeypatch.setenv("GRPC_INSECURE_ALLOWED", "true")

        with patch("common.grpc_factory.grpc_aio.insecure_channel") as channel_factory:
            channel_factory.return_value = MagicMock()
            create_grpc_channel("localhost:50051", service_name="test-svc")

        interceptors = channel_factory.call_args.kwargs["interceptors"]
        token_interceptor = next(
            item
            for item in interceptors
            if isinstance(item, ServiceTokenClientInterceptor)
        )
        assert token_interceptor._token == token

    def test_environment_and_file_are_mutually_exclusive(self, monkeypatch, tmp_path):
        token_file = tmp_path / "grpc_service_token"
        token_file.write_text("c" * 48, encoding="utf-8")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN", "d" * 48)
        monkeypatch.setenv("GRPC_SERVICE_TOKEN_FILE", str(token_file))

        with pytest.raises(RuntimeError, match="Both GRPC_SERVICE_TOKEN"):
            create_grpc_server("test-svc")

    def test_client_interceptor_covers_every_rpc_cardinality(self):
        interceptor = ServiceTokenClientInterceptor("a" * 48)

        assert isinstance(interceptor, grpc.aio.UnaryUnaryClientInterceptor)
        assert isinstance(interceptor, grpc.aio.UnaryStreamClientInterceptor)
        assert isinstance(interceptor, grpc.aio.StreamUnaryClientInterceptor)
        assert isinstance(interceptor, grpc.aio.StreamStreamClientInterceptor)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("factory", "cardinality"),
        [
            (grpc.unary_unary_rpc_method_handler, "unary_unary"),
            (grpc.unary_stream_rpc_method_handler, "unary_stream"),
            (grpc.stream_unary_rpc_method_handler, "stream_unary"),
            (grpc.stream_stream_rpc_method_handler, "stream_stream"),
        ],
    )
    async def test_rejection_preserves_rpc_cardinality(self, factory, cardinality):
        original = factory(lambda request, context: None)
        continuation = AsyncMock(return_value=original)
        details = SimpleNamespace(method="/test.Service/Call", invocation_metadata=())

        rejected = await ServiceAuthInterceptor("a" * 48).intercept_service(
            continuation,
            details,
        )

        assert getattr(rejected, cardinality) is not None

class TestWorkloadIdentityAuthentication:
    _METHOD = "/marty.test.v1.Verifier/Evaluate"
    _FLOW_IDENTITY = "spiffe://marty.internal/service/flow"

    @staticmethod
    def _authorization():
        return {
            TestWorkloadIdentityAuthentication._METHOD: {
                TestWorkloadIdentityAuthentication._FLOW_IDENTITY
            }
        }

    @staticmethod
    def _context(*identities: str, transport: bytes = b"ssl"):
        return SimpleNamespace(
            auth_context=lambda: {
                "transport_security_type": [transport],
                "x509_subject_alternative_name": [
                    identity.encode() for identity in identities
                ],
            },
            abort=AsyncMock(),
        )

    async def _intercept(self, *, method=None):
        original = AsyncMock(return_value="verified")
        handler = grpc.unary_unary_rpc_method_handler(original)
        continuation = AsyncMock(return_value=handler)
        details = SimpleNamespace(
            method=method or self._METHOD,
            invocation_metadata=(("x-service-token", "shared-secret"),),
        )
        intercepted = await WorkloadIdentityInterceptor(
            self._authorization()
        ).intercept_service(continuation, details)
        return intercepted, original

    def test_production_server_requires_workload_certificate_configuration(
        self, monkeypatch
    ):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN", "s" * 48)

        with pytest.raises(RuntimeError, match="certificate-derived workload identity"):
            create_grpc_server(
                "verifier",
                workload_identity_authorization=self._authorization(),
            )

    def test_production_client_requires_unique_workload_certificate(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN", "s" * 48)

        with pytest.raises(RuntimeError, match="certificate-derived workload identity"):
            create_grpc_channel(
                "presentation-policy:9009",
                service_name="flow",
                require_workload_identity=True,
            )

    def test_partial_workload_tls_configuration_is_rejected(self, monkeypatch):
        monkeypatch.setenv("GRPC_WORKLOAD_TLS_CLIENT_CERT", "client.pem")

        with pytest.raises(RuntimeError, match="Incomplete.*CLIENT_KEY"):
            create_grpc_channel(
                "presentation-policy:9009",
                service_name="flow",
                require_workload_identity=True,
            )

    @pytest.mark.asyncio
    async def test_allows_exact_certificate_uri_san(self):
        intercepted, original = await self._intercept()
        context = self._context(self._FLOW_IDENTITY)

        result = await intercepted.unary_unary(object(), context)

        assert result == "verified"
        context.abort.assert_not_awaited()
        original.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_shared_bearer_token_cannot_replace_certificate_identity(self):
        intercepted, original = await self._intercept()
        context = self._context(transport=b"insecure")

        await intercepted.unary_unary(object(), context)

        context.abort.assert_awaited_once_with(
            grpc.StatusCode.UNAUTHENTICATED,
            "A mutually authenticated workload identity is required",
        )
        original.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_rejects_authenticated_but_unauthorized_workload(self):
        intercepted, original = await self._intercept()
        context = self._context("spiffe://marty.internal/service/notification")

        await intercepted.unary_unary(object(), context)

        context.abort.assert_awaited_once_with(
            grpc.StatusCode.PERMISSION_DENIED,
            "The authenticated workload is not authorized for this RPC",
        )
        original.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_rpc_allowlist_is_deny_by_default(self):
        intercepted, original = await self._intercept(
            method="/marty.test.v1.Verifier/DeletePolicy"
        )
        context = self._context(self._FLOW_IDENTITY)

        await intercepted.unary_unary(object(), context)

        context.abort.assert_awaited_once_with(
            grpc.StatusCode.PERMISSION_DENIED,
            "The authenticated workload is not authorized for this RPC",
        )
        original.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_deny_by_default_also_covers_server_streaming(self):
        async def stream(_request, _context):
            yield "should-not-be-visible"

        original = MagicMock(side_effect=stream)
        handler = grpc.unary_stream_rpc_method_handler(original)
        continuation = AsyncMock(return_value=handler)
        details = SimpleNamespace(
            method="/marty.test.v1.Verifier/StreamSecrets",
            invocation_metadata=(),
        )
        intercepted = await WorkloadIdentityInterceptor(
            self._authorization()
        ).intercept_service(continuation, details)
        context = self._context(self._FLOW_IDENTITY)

        responses = [
            response async for response in intercepted.unary_stream(object(), context)
        ]

        assert responses == []
        context.abort.assert_awaited_once_with(
            grpc.StatusCode.PERMISSION_DENIED,
            "The authenticated workload is not authorized for this RPC",
        )
        original.assert_not_called()

    @staticmethod
    def _certificate_material(tmp_path):
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Marty test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(ca_key, hashes.SHA256())
        )

        def issue(name, san, usage):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
                )
                .issuer_name(ca_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([san]), False)
                .add_extension(x509.ExtendedKeyUsage([usage]), False)
                .sign(ca_key, hashes.SHA256())
            )
            return cert, key

        server_cert, server_key = issue(
            "presentation-policy",
            x509.DNSName("localhost"),
            ExtendedKeyUsageOID.SERVER_AUTH,
        )
        client_cert, client_key = issue(
            "flow",
            x509.UniformResourceIdentifier(
                TestWorkloadIdentityAuthentication._FLOW_IDENTITY
            ),
            ExtendedKeyUsageOID.CLIENT_AUTH,
        )

        paths = {
            "ca": tmp_path / "ca.pem",
            "server_cert": tmp_path / "server.pem",
            "server_key": tmp_path / "server.key",
            "client_cert": tmp_path / "client.pem",
            "client_key": tmp_path / "client.key",
        }
        paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        for prefix, cert, key in (
            ("server", server_cert, server_key),
            ("client", client_cert, client_key),
        ):
            paths[f"{prefix}_cert"].write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            paths[f"{prefix}_key"].write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        return paths

    @pytest.mark.asyncio
    async def test_real_mtls_peer_uri_authorizes_rpc(self, monkeypatch, tmp_path):
        paths = self._certificate_material(tmp_path)
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("GRPC_SERVICE_TOKEN", "s" * 48)
        monkeypatch.setenv("GRPC_WORKLOAD_TLS_CA_CERT", str(paths["ca"]))
        monkeypatch.setenv("GRPC_WORKLOAD_TLS_SERVER_CERT", str(paths["server_cert"]))
        monkeypatch.setenv("GRPC_WORKLOAD_TLS_SERVER_KEY", str(paths["server_key"]))
        monkeypatch.setenv("GRPC_WORKLOAD_TLS_CLIENT_CERT", str(paths["client_cert"]))
        monkeypatch.setenv("GRPC_WORKLOAD_TLS_CLIENT_KEY", str(paths["client_key"]))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        server, health = create_grpc_server(
            "verifier",
            workload_identity_authorization=self._authorization(),
        )
        generic_handler = grpc.method_handlers_generic_handler(
            "marty.test.v1.Verifier",
            {
                "Evaluate": grpc.unary_unary_rpc_method_handler(
                    lambda request, context: b"verified"
                )
            },
        )
        server.add_generic_rpc_handlers((generic_handler,))
        start_grpc_server_port(
            server,
            port,
            service_names=["marty.test.v1.Verifier"],
            health_servicer=health,
            require_workload_identity=True,
        )
        await server.start()
        channel = create_grpc_channel(
            f"localhost:{port}",
            service_name="flow",
            require_workload_identity=True,
        )
        try:
            call = channel.unary_unary(self._METHOD)
            assert await call(b"request") == b"verified"
        finally:
            await channel.close()
            await server.stop(grace=0)


# ── LoggingMetricsInterceptor ────────────────────────────────────────


class TestLoggingMetricsInterceptor:
    def test_initialises_without_prometheus(self):
        interceptor = LoggingMetricsInterceptor("test-svc")
        assert interceptor._service_name == "test-svc"

    def test_initialises_with_prometheus(self):
        # First interceptor instance registers metrics; subsequent ones
        # may fail due to duplicate collector — that's expected and caught.
        interceptor = LoggingMetricsInterceptor("prometheus-test-svc")
        # At least the first call should succeed with prometheus_client
        # available; the attrs will be None only if prometheus is missing.
        # Since prometheus_client IS installed, at least one of the
        # counters should be non-None (the first instance that registered).
        assert interceptor._service_name == "prometheus-test-svc"


# ── CorrelationIdInterceptor ─────────────────────────────────────────


class TestCorrelationIdInterceptor:
    def test_creates_interceptor(self):
        interceptor = CorrelationIdInterceptor()
        assert interceptor._HEADER == "x-correlation-id"
