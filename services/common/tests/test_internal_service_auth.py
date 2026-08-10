from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from common.internal_service_auth import (
    internal_service_headers,
    require_internal_service_auth,
)


def _client() -> TestClient:
    app = FastAPI()

    @app.get("/internal", dependencies=[Depends(require_internal_service_auth)])
    def internal_endpoint() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def test_internal_http_auth_allows_tokenless_test_composition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("GRPC_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("GRPC_SERVICE_TOKEN_FILE", raising=False)

    assert _client().get("/internal").status_code == 200
    assert internal_service_headers() == {}


def test_internal_http_auth_requires_production_service_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "a" * 48
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("GRPC_SERVICE_TOKEN", token)
    monkeypatch.delenv("GRPC_SERVICE_TOKEN_FILE", raising=False)
    client = _client()

    assert client.get("/internal").status_code == 401
    assert client.get("/internal", headers={"x-service-token": "wrong"}).status_code == 401
    assert client.get("/internal", headers=internal_service_headers()).status_code == 200
