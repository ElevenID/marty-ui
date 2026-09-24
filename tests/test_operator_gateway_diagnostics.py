from __future__ import annotations

import importlib
import logging
import sys
import types
from dataclasses import dataclass
from typing import Any

import httpx

from scripts import debug_issuance_response as debug_issuance
from scripts.operator_gateway import (
    GatewayActorConfigurationError,
    resolve_gateway_actor,
)


@dataclass
class Response:
    status_code: int
    body: Any

    def json(self) -> Any:
        if isinstance(self.body, ValueError):
            raise self.body
        return self.body


class RecordingClient:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __enter__(self) -> "RecordingClient":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def post(self, url: str, **kwargs: Any) -> Response:
        self.calls.append((url, kwargs))
        return self.response


class TransportFailureClient(RecordingClient):
    def post(self, url: str, **_kwargs: Any) -> Response:
        raise httpx.ConnectError(
            "private transport detail", request=httpx.Request("POST", url)
        )


def import_canvas_seed(monkeypatch):
    package = types.ModuleType("marty_common")
    system_ids = types.ModuleType("marty_common.system_ids")
    for name in [
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID",
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID",
        "MARTY_DEFAULT_ORG_ID",
        "MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID",
        "MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID",
    ]:
        setattr(system_ids, name, f"synthetic-{name.lower()}")
    monkeypatch.setitem(sys.modules, "marty_common", package)
    monkeypatch.setitem(sys.modules, "marty_common.system_ids", system_ids)
    sys.modules.pop("scripts.seed_canvas_real", None)
    return importlib.import_module("scripts.seed_canvas_real")


def test_shared_gateway_actor_rejects_service_credential_only_configuration() -> None:
    environment = {
        "ISSUANCE_API_KEY": "private-service-key",
        "ISSUANCE_API_BASE_URL": "http://legacy-issuance:8005",
    }
    try:
        resolve_gateway_actor(environment, required_scopes=("credentials:issue",))
    except GatewayActorConfigurationError as error:
        rendered = str(error)
    else:
        raise AssertionError("service credential must not authenticate a gateway actor")

    assert "MARTY_API_KEY is required" in rendered
    assert "private-service-key" not in rendered
    assert "legacy-issuance" not in rendered


def test_debug_diagnostic_authenticates_gateway_and_redacts_secrets(
    monkeypatch, caplog
) -> None:
    monkeypatch.setenv("MARTY_API_BASE_URL", "https://gateway.example/")
    monkeypatch.setenv("MARTY_API_KEY", "private-gateway-actor-key")
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-service-key")
    client = RecordingClient(
        Response(
            200,
            {
                "credential_offer_uri": "private-offer-uri",
                "credential_offer_uris": {"wallet-a": "private-wallet-offer"},
                "credential_offer_labels": {"wallet-a": "Wallet A"},
            },
        )
    )
    caplog.set_level(logging.INFO)

    assert debug_issuance.main(lambda **_kwargs: client) == 0
    assert client.calls[0][0] == "https://gateway.example/v1/issuance/initiate"
    assert client.calls[0][1]["headers"] == {"X-API-Key": "private-gateway-actor-key"}
    for secret in [
        "private-gateway-actor-key",
        "private-service-key",
        "private-offer-uri",
        "private-wallet-offer",
    ]:
        assert secret not in caplog.text


def test_debug_and_canvas_seed_fail_fast_with_only_service_key(
    monkeypatch, caplog, capsys
) -> None:
    monkeypatch.delenv("MARTY_API_KEY", raising=False)
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-service-key")
    debug_factory_called = False

    def client_factory(**_kwargs: Any) -> RecordingClient:
        nonlocal debug_factory_called
        debug_factory_called = True
        raise AssertionError("debug diagnostic must fail before HTTP")

    caplog.set_level(logging.INFO)
    assert debug_issuance.main(client_factory) == 2
    assert not debug_factory_called
    assert "private-service-key" not in caplog.text

    seed_canvas_real = import_canvas_seed(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["seed_canvas_real.py", "--skip-canvas-lms-seed"])
    assert seed_canvas_real.main() == 2
    assert "private-service-key" not in capsys.readouterr().out


def test_debug_diagnostic_handles_transport_status_and_json_failures_without_leaks(
    monkeypatch, caplog
) -> None:
    monkeypatch.setenv("MARTY_API_KEY", "private-gateway-actor-key")
    caplog.set_level(logging.INFO)
    transport = TransportFailureClient(Response(200, {}))
    assert debug_issuance.main(lambda **_kwargs: transport) == 1
    status = RecordingClient(Response(503, ValueError("private non-json response")))
    assert debug_issuance.main(lambda **_kwargs: status) == 1
    malformed = RecordingClient(Response(200, ValueError("private malformed JSON")))
    assert debug_issuance.main(lambda **_kwargs: malformed) == 1
    for secret in [
        "private-gateway-actor-key",
        "private transport detail",
        "private non-json response",
        "private malformed JSON",
    ]:
        assert secret not in caplog.text


def test_canvas_seed_keeps_internal_application_credentials_separate(
    monkeypatch,
) -> None:
    seed_canvas_real = import_canvas_seed(monkeypatch)
    monkeypatch.setenv("MARTY_API_BASE_URL", "https://gateway.example")
    monkeypatch.setenv("MARTY_API_KEY", "private-gateway-actor-key")
    monkeypatch.setenv("ISSUANCE_INTERNAL_API_BASE_URL", "http://issuance-native:8005")
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-service-key")
    gateway = seed_canvas_real.resolve_gateway_actor(
        required_scopes=("integrations:write",)
    )
    assert gateway.base_url == "https://gateway.example"
    assert gateway.api_key == "private-gateway-actor-key"

    source = open(seed_canvas_real.__file__, encoding="utf-8").read()
    assert "connector_cfg.internal_issuance_base_url" in source
    assert "connector_cfg.internal_issuance_api_key" in source


def test_canvas_seed_rejects_missing_or_gateway_routed_internal_configuration(
    monkeypatch, capsys
) -> None:
    seed_canvas_real = import_canvas_seed(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["seed_canvas_real.py", "--skip-canvas-lms-seed"])
    monkeypatch.setenv("MARTY_API_KEY", "private-gateway-actor-key")
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-service-key")
    monkeypatch.delenv("ISSUANCE_INTERNAL_API_BASE_URL", raising=False)
    assert seed_canvas_real.main() == 2

    monkeypatch.setenv("MARTY_API_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("ISSUANCE_INTERNAL_API_BASE_URL", "http://localhost:8000/")
    assert seed_canvas_real.main() == 2
    output = capsys.readouterr().out
    assert "private-gateway-actor-key" not in output
    assert "private-service-key" not in output
