from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import pytest

from scripts import check_template_wallets as diagnostic


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

    def get(self, url: str, **kwargs: Any) -> Response:
        self.calls.append((url, kwargs))
        return self.response


def test_wallet_diagnostic_reads_typed_compatibility_through_gateway(
    monkeypatch, caplog
) -> None:
    monkeypatch.setenv("MARTY_API_BASE_URL", "https://gateway.example/")
    monkeypatch.setenv("MARTY_API_KEY", "private-actor-key")
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-service-key")
    monkeypatch.setenv("MARTY_CREDENTIAL_TEMPLATE_ID", "template-1")
    monkeypatch.setenv("MARTY_ORGANIZATION_ID", "org-1")
    client = RecordingClient(
        Response(
            200,
            {
                "template_wallet_configs": [
                    {
                        "wallet_id": "wallet-a",
                        "deep_link_scheme": "openid-credential-offer://",
                        "format_variant": "dc+sd-jwt",
                    }
                ]
            },
        )
    )
    caplog.set_level(logging.INFO)

    assert diagnostic.main(lambda **_kwargs: client) == 0
    assert client.calls == [
        (
            "https://gateway.example/v1/credential-templates/template-1/wallet-compatibility",
            {
                "params": {"organization_id": "org-1"},
                "headers": {"X-API-Key": "private-actor-key"},
            },
        )
    ]
    assert "wallet-a" in caplog.text
    assert "private-actor-key" not in caplog.text
    assert "private-service-key" not in caplog.text


def test_wallet_diagnostic_treats_typed_empty_array_as_meaningful(
    monkeypatch, caplog
) -> None:
    monkeypatch.setenv("MARTY_API_KEY", "private-actor-key")
    client = RecordingClient(Response(200, {"template_wallet_configs": []}))
    caplog.set_level(logging.INFO)

    assert diagnostic.main(lambda **_kwargs: client) == 0
    assert "No template wallet configurations are effective" in caplog.text
    assert "private-actor-key" not in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        ValueError("private malformed body"),
        [],
        {},
        {"template_wallet_configs": "not-an-array"},
        {"template_wallet_configs": ["not-an-object"]},
        {
            "template_wallet_configs": [
                {"wallet_id": "", "deep_link_scheme": "openid-credential-offer://"}
            ]
        },
        {"template_wallet_configs": [{"wallet_id": "wallet-a", "deep_link_scheme": 7}]},
        {
            "template_wallet_configs": [
                {
                    "wallet_id": "wallet-a",
                    "deep_link_scheme": "openid-credential-offer://",
                    "format_variant": 7,
                }
            ]
        },
    ],
)
def test_wallet_diagnostic_rejects_malformed_compatibility(
    monkeypatch, caplog, body
) -> None:
    monkeypatch.setenv("MARTY_API_KEY", "private-actor-key")
    client = RecordingClient(Response(200, body))
    caplog.set_level(logging.INFO)

    assert diagnostic.main(lambda **_kwargs: client) == 1
    assert "private-actor-key" not in caplog.text
    assert "private malformed body" not in caplog.text


def test_wallet_diagnostic_rejects_status_and_service_key_only_without_leaks(
    monkeypatch, caplog
) -> None:
    monkeypatch.setenv("MARTY_API_KEY", "private-actor-key")
    client = RecordingClient(Response(403, {"detail": "private upstream detail"}))
    caplog.set_level(logging.INFO)
    assert diagnostic.main(lambda **_kwargs: client) == 1
    assert "private upstream detail" not in caplog.text

    monkeypatch.delenv("MARTY_API_KEY")
    monkeypatch.setenv("ISSUANCE_API_KEY", "private-service-key")
    unused = RecordingClient(Response(200, {}))
    assert diagnostic.main(lambda **_kwargs: unused) == 2
    assert unused.calls == []
    assert "private-service-key" not in caplog.text
