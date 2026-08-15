"""Fail-closed adapter for the canonical Rust trust-registry kernel."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from common.native_backend import (
    NativeBackendUnavailable,
    NativeOperationError,
    get_marty_rs_diagnostics,
    load_marty_rs,
)

NATIVE_CAPABILITY = "trust_registry_sync"
T = TypeVar("T")


def diagnostics() -> dict[str, Any]:
    backend = load_marty_rs(required_capability=NATIVE_CAPABILITY)
    return get_marty_rs_diagnostics(backend, required_capability=NATIVE_CAPABILITY)


def _function(name: str) -> Any:
    backend = load_marty_rs(required_capability=NATIVE_CAPABILITY)
    function = getattr(backend, name, None)
    if not callable(function):
        raise NativeBackendUnavailable(
            f"The Marty Rust trust-registry backend does not expose {name}"
        )
    return function


def _text(name: str, *args: object) -> str:
    try:
        result = _function(name)(*args)
    except (NativeBackendUnavailable, NativeOperationError):
        raise
    except Exception as error:
        raise NativeOperationError(str(error)) from error
    if not isinstance(result, str):
        raise NativeOperationError(f"Rust trust-registry {name} result is malformed")
    return result


def _json(name: str, expected: type[T], *args: object) -> T:
    try:
        result = json.loads(_text(name, *args))
    except json.JSONDecodeError as error:
        raise NativeOperationError(
            f"Rust trust-registry {name} returned invalid JSON"
        ) from error
    if not isinstance(result, expected):
        raise NativeOperationError(f"Rust trust-registry {name} result is malformed")
    return result


def behavior_fixture() -> dict[str, Any]:
    return _json("trust_registry_behavior_fixture_json", dict)


def registry_catalog(framework: str | None = None) -> list[dict[str, Any]]:
    return _json("trust_registry_catalog_json", list, framework)


def import_decision(
    registry_type: str,
    now_rfc3339: str,
    requested_formats: list[str] | None = None,
    sync_interval_hours: int | None = None,
) -> dict[str, Any]:
    formats = json.dumps(requested_formats) if requested_formats is not None else None
    return _json(
        "trust_registry_import_decision_json",
        dict,
        registry_type,
        now_rfc3339,
        formats,
        sync_interval_hours,
    )


def public_sync_query(since: str | None) -> dict[str, Any]:
    return _json("trust_registry_public_sync_query_json", dict, since)


def public_sync_metadata(sequence: int, generated_at: str) -> dict[str, Any]:
    return _json(
        "trust_registry_public_sync_metadata_json", dict, sequence, generated_at
    )


def sync_is_due(interval: int, now: str, last_sync: str | None) -> bool:
    return _json("trust_registry_sync_is_due_json", bool, interval, now, last_sync)


def validate_url(url: str) -> str:
    return _text("trust_registry_validate_url", url)


def destination_decision(
    url: str, addresses: list[str], private_allowlist: str
) -> dict[str, Any]:
    return _json(
        "trust_registry_destination_decision_json",
        dict,
        url,
        json.dumps(addresses),
        private_allowlist,
    )


def validate_private_host_allowlist(configured: str) -> list[str]:
    return _json("trust_registry_private_host_allowlist_json", list, configured)


def request_plan(url: str, token: str | None, address: str | None) -> dict[str, Any]:
    return _json("trust_registry_request_plan_json", dict, url, token, address)


def validate_feed(raw_json: str) -> dict[str, Any]:
    return _json("trust_registry_validate_feed_json", dict, raw_json)


def validate_state(state: dict[str, Any]) -> dict[str, Any]:
    return _json("trust_registry_validate_state_json", dict, json.dumps(state))


def evaluate_pages(
    previous_state: dict[str, Any], pages: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    return _json(
        "trust_registry_evaluate_pages_json",
        dict,
        json.dumps(previous_state),
        json.dumps(pages),
        now,
    )


def revalidate_state(state: dict[str, Any], now: str) -> dict[str, Any]:
    return _json("trust_registry_revalidate_state_json", dict, json.dumps(state), now)
