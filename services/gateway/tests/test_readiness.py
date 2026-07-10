"""Tests for gateway readiness dependency checks."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

import gateway.main as gateway_main


class _Registry:
    def __init__(self, urls: dict[str, str | None]):
        self._urls = urls

    def get_service_url(self, service_name: str) -> str | None:
        return self._urls.get(service_name)


class _HealthClient:
    def __init__(self, statuses: dict[str, int | Exception]):
        self._statuses = statuses

    async def get(self, url: str, timeout: float, **kwargs):
        del timeout
        del kwargs
        status = self._statuses[url]
        if isinstance(status, Exception):
            raise status
        return SimpleNamespace(status_code=status)


class _Redis:
    def __init__(self, error: Exception | None = None):
        self.error = error

    async def ping(self):
        if self.error:
            raise self.error
        return True


async def _get(app, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


@pytest.mark.asyncio
async def test_ready_returns_json_when_required_services_are_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    app = gateway_main.create_app()
    monkeypatch.setattr(gateway_main, "_required_ready_services", lambda: ("organizations", "auth"))
    monkeypatch.setattr(
        gateway_main,
        "get_registry",
        lambda: _Registry(
            {
                "organizations": "http://organization:8002",
                "auth": "http://auth:8001",
            }
        ),
    )
    monkeypatch.setattr(
        gateway_main,
        "get_http_client",
        lambda: _HealthClient(
            {
                "http://organization:8002/health": 200,
                "http://auth:8001/health": 200,
            }
        ),
    )

    response = await _get(app, "/ready")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["status"] == "ready"
    assert body["services"]["organizations"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_ready_returns_503_when_required_service_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    app = gateway_main.create_app()
    monkeypatch.setattr(gateway_main, "_required_ready_services", lambda: ("organizations", "auth"))
    monkeypatch.setattr(
        gateway_main,
        "get_registry",
        lambda: _Registry(
            {
                "organizations": "http://organization:8002",
                "auth": "http://auth:8001",
            }
        ),
    )
    monkeypatch.setattr(
        gateway_main,
        "get_http_client",
        lambda: _HealthClient(
            {
                "http://organization:8002/health": httpx.ConnectError("connection refused"),
                "http://auth:8001/health": 200,
            }
        ),
    )

    response = await _get(app, "/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["services"]["organizations"]["status"] == "unreachable"
    assert body["services"]["organizations"]["url"] == "http://organization:8002"
    assert body["services"]["auth"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_ready_checks_gateway_local_signing_keys_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    app = gateway_main.create_app()
    app.state.redis_client = _Redis()
    monkeypatch.setattr(gateway_main, "_required_ready_services", lambda: ("signing-keys",))
    monkeypatch.setattr(gateway_main, "get_http_client", lambda: _HealthClient({}))
    monkeypatch.delenv("BAO_ADDR", raising=False)

    response = await _get(app, "/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["services"]["signing-keys"]["status"] == "healthy"
    assert body["services"]["signing-keys"]["mode"] == "gateway-local"


@pytest.mark.asyncio
async def test_health_ready_fails_when_openbao_is_sealed(monkeypatch: pytest.MonkeyPatch) -> None:
    app = gateway_main.create_app()
    app.state.redis_client = _Redis()
    monkeypatch.setattr(gateway_main, "_required_ready_services", lambda: ("signing-keys",))
    monkeypatch.setenv("BAO_ADDR", "http://openbao:8200")
    monkeypatch.setattr(
        gateway_main,
        "get_http_client",
        lambda: _HealthClient({"http://openbao:8200/v1/sys/health": 503}),
    )

    response = await _get(app, "/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["services"]["signing-keys"]["status"] == "unhealthy"
    assert body["services"]["signing-keys"]["openbao_status_code"] == 503
