"""Marty-owned tests for purpose-scoped notification event authentication."""

from __future__ import annotations

from pathlib import Path

import pytest

from common.notification_event_auth import (
    NotificationEventAuthConfigurationError,
    notification_event_ingest_headers,
    read_notification_event_ingest_token,
)


def _clear_token_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTIFICATION_EVENT_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("NOTIFICATION_EVENT_INGEST_TOKEN_FILE", raising=False)


def test_token_can_be_loaded_from_a_dedicated_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_token_sources(monkeypatch)
    token_file = tmp_path / "notification_event_ingest_token"
    token_file.write_text("t" * 48, encoding="utf-8")
    monkeypatch.setenv("NOTIFICATION_EVENT_INGEST_TOKEN_FILE", str(token_file))

    assert read_notification_event_ingest_token() == "t" * 48
    assert notification_event_ingest_headers() == {"X-Service-Token": "t" * 48}


@pytest.mark.parametrize(
    "token",
    ["", "short", "change-me-notification-event-ingest-token"],
)
def test_missing_weak_or_placeholder_tokens_fail_closed(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    _clear_token_sources(monkeypatch)
    if token:
        monkeypatch.setenv("NOTIFICATION_EVENT_INGEST_TOKEN", token)

    with pytest.raises(NotificationEventAuthConfigurationError):
        read_notification_event_ingest_token()


def test_ambiguous_token_sources_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_file = tmp_path / "notification_event_ingest_token"
    token_file.write_text("f" * 48, encoding="utf-8")
    monkeypatch.setenv("NOTIFICATION_EVENT_INGEST_TOKEN", "e" * 48)
    monkeypatch.setenv("NOTIFICATION_EVENT_INGEST_TOKEN_FILE", str(token_file))

    with pytest.raises(NotificationEventAuthConfigurationError):
        read_notification_event_ingest_token()
