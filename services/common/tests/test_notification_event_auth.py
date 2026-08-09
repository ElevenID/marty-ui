"""Marty-owned tests for purpose-scoped notification event authentication."""

from __future__ import annotations

from pathlib import Path

import pytest

from common.notification_event_auth import (
    NotificationEventAuthConfigurationError,
    notification_event_ingest_headers,
    read_applicant_event_token,
    read_notification_event_producer_id,
)


def _clear_token_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", raising=False)
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE", raising=False)


def test_token_can_be_loaded_from_a_dedicated_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_token_sources(monkeypatch)
    token_file = tmp_path / "notification_applicant_event_token"
    token_file.write_text("t" * 48, encoding="utf-8")
    monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("NOTIFICATION_EVENT_PRODUCER_ID", "applicant")

    assert read_applicant_event_token() == "t" * 48
    assert read_notification_event_producer_id() == "applicant"
    assert notification_event_ingest_headers() == {
        "X-Service-Token": "t" * 48,
        "X-Marty-Event-Producer": "applicant",
    }


@pytest.mark.parametrize(
    "token",
    ["", "short", "change-me-notification-event-ingest-token"],
)
def test_missing_weak_or_placeholder_tokens_fail_closed(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    _clear_token_sources(monkeypatch)
    if token:
        monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", token)

    with pytest.raises(NotificationEventAuthConfigurationError):
        read_applicant_event_token()


def test_ambiguous_token_sources_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_file = tmp_path / "notification_applicant_event_token"
    token_file.write_text("f" * 48, encoding="utf-8")
    monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", "e" * 48)
    monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE", str(token_file))

    with pytest.raises(NotificationEventAuthConfigurationError):
        read_applicant_event_token()


def test_retired_generic_ingest_token_is_not_a_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_token_sources(monkeypatch)
    monkeypatch.setenv("NOTIFICATION_EVENT_INGEST_TOKEN", "g" * 48)

    with pytest.raises(NotificationEventAuthConfigurationError):
        read_applicant_event_token()


@pytest.mark.parametrize("producer_id", ["", "credential", "Applicant"])
def test_missing_or_unsupported_producer_identity_fails_closed(
    monkeypatch: pytest.MonkeyPatch, producer_id: str
) -> None:
    monkeypatch.delenv("NOTIFICATION_EVENT_PRODUCER_ID", raising=False)
    if producer_id:
        monkeypatch.setenv("NOTIFICATION_EVENT_PRODUCER_ID", producer_id)

    with pytest.raises(NotificationEventAuthConfigurationError):
        read_notification_event_producer_id()
