from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from scripts import test_credential_format as diagnostic


@dataclass
class Response:
    status_code: int
    body: Any
    text: str = ""

    def json(self) -> Any:
        if isinstance(self.body, ValueError):
            raise self.body
        return self.body


class RecordingHttpClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses = iter(
            [
                Response(200, {"pre_auth_code": "private-pre-auth-code"}),
                Response(200, {"access_token": "private-access-token"}),
                Response(200, {"credential": "eyJ0eXAiOiJkYytzZC1qd3QifQ.payload"}),
            ]
        )

    def post(self, url: str, **kwargs: Any) -> Response:
        self.calls.append((url, kwargs))
        return next(self.responses)


class TransportFailureClient:
    def post(self, url: str, **_kwargs: Any) -> Response:
        raise httpx.ConnectError(
            "private transport detail", request=httpx.Request("POST", url)
        )


def test_diagnostic_uses_authenticated_gateway_without_logging_secrets(
    monkeypatch, capsys
) -> None:
    monkeypatch.setenv("MARTY_API_BASE_URL", "https://gateway.example/")
    monkeypatch.setenv("ISSUANCE_API_BASE_URL", "https://legacy-direct.example")
    monkeypatch.setenv("MARTY_API_KEY", "private-marty-key")
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-compatibility-key")
    client = RecordingHttpClient()

    assert diagnostic.main(client) == 0
    assert client.calls[0][0] == "https://gateway.example/v1/issuance/initiate"
    assert client.calls[0][1]["headers"] == {"X-API-Key": "private-marty-key"}
    assert client.calls[1][0] == "https://gateway.example/v1/issuance/token"
    assert client.calls[2][0] == "https://gateway.example/v1/issuance/credential"

    output = capsys.readouterr().out
    for secret in [
        "private-marty-key",
        "private-compatibility-key",
        "private-pre-auth-code",
        "private-access-token",
    ]:
        assert secret not in output


def test_diagnostic_rejects_service_key_only_and_accepts_gateway_actor_key(
    monkeypatch, capsys
) -> None:
    monkeypatch.delenv("MARTY_API_BASE_URL", raising=False)
    monkeypatch.delenv("ISSUANCE_API_BASE_URL", raising=False)
    monkeypatch.delenv("MARTY_API_KEY", raising=False)
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-local-stack-key")
    empty_client = RecordingHttpClient()
    assert diagnostic.main(empty_client) == 2
    assert empty_client.calls == []
    assert "private-local-stack-key" not in capsys.readouterr().out

    monkeypatch.setenv("MARTY_API_KEY", "private-gateway-actor-key")
    client = RecordingHttpClient()
    assert diagnostic.main(client) == 0
    assert client.calls[0][0] == "http://localhost:8000/v1/issuance/initiate"
    assert client.calls[0][1]["headers"] == {"X-API-Key": "private-gateway-actor-key"}
    assert "private-gateway-actor-key" not in capsys.readouterr().out


def test_diagnostic_handles_transport_status_and_json_failures_without_leaks(
    monkeypatch, capsys
) -> None:
    monkeypatch.setenv("MARTY_API_KEY", "private-gateway-actor-key")
    assert diagnostic.main(TransportFailureClient()) == 1

    status_client = RecordingHttpClient()
    status_client.responses = iter(
        [
            Response(
                503, ValueError("private non-json response"), "private response body"
            )
        ]
    )
    assert diagnostic.main(status_client) == 1

    malformed_client = RecordingHttpClient()
    malformed_client.responses = iter(
        [Response(200, ValueError("private malformed JSON"))]
    )
    assert diagnostic.main(malformed_client) == 1
    output = capsys.readouterr().out
    for secret in [
        "private-gateway-actor-key",
        "private transport detail",
        "private non-json response",
        "private response body",
        "private malformed JSON",
    ]:
        assert secret not in output
