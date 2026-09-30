"""Durable beta fence rejection receipts must bind exact observations."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts.probe_passport_beta_fence_direct_writes import (
    ERRORS, FenceProbeError, verify_receipt,
)


CONTAINER = "a" * 64
TARGET = {
    "postgres_container_id": CONTAINER,
    "expected_docker_context": "beta-context",
    "expected_daemon_id": "beta-daemon",
    "expected_system_identifier": "12345",
    "expected_database_oid": "67890",
    "expected_fence_epoch": 3,
}


def receipt_bytes(**changes: object) -> bytes:
    receipt = {
        "schema": "marty.passport-beta-fence-direct-probe/v1",
        "method": "postgresql_transaction_rollback",
        "docker_context": "beta-context",
        "docker_daemon_id": "beta-daemon",
        "postgres_container_id": CONTAINER,
        "database_uid": "postgresql:12345:67890",
        "fence_epoch": 3,
        "observation_watermark": 200,
        "observed_at_utc": "2026-09-30T06:00:00.000Z",
        "session_user": "marty",
        "current_user": "marty",
        "probe_nonce": "b" * 32,
        "rejections": {
            surface: {"valid_without_fence": True, "sqlstate": "55000",
                      "message": message}
            for surface, message in ERRORS.items()
        },
    }
    receipt.update(changes)
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_verifies_exact_rejections_and_canonical_digest() -> None:
    payload = receipt_bytes()
    checked = verify_receipt(payload, **TARGET)
    assert checked["verified"] is True
    assert checked["receipt_file_sha256"] == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("changes", [
    {"rejections": {}},
    {"rejections": {
        surface: {"valid_without_fence": 1, "sqlstate": "55000",
                  "message": message}
        for surface, message in ERRORS.items()
    }},
    {"method": "no_rollback"},
    {"observation_watermark": True},
    {"fence_epoch": True},
    {"probe_nonce": "invalid"},
    {"docker_context": "another-context"},
])
def test_rejects_altered_observation_even_with_recomputed_hash(
    changes: dict[str, object],
) -> None:
    with pytest.raises(FenceProbeError):
        verify_receipt(receipt_bytes(**changes), **TARGET)


def test_rejects_changed_hash() -> None:
    payload = json.loads(receipt_bytes())
    payload["receipt_sha256"] = "0" * 64
    with pytest.raises(FenceProbeError, match="canonical hash"):
        verify_receipt(json.dumps(payload).encode(), **TARGET)


def test_rejects_duplicate_fields_at_any_depth() -> None:
    payload = receipt_bytes().decode()
    top_level = payload.replace('"method":', '"method":"no_rollback","method":', 1)
    nested = payload.replace('"sqlstate":', '"sqlstate":"00000","sqlstate":', 1)
    for changed in (top_level, nested):
        with pytest.raises(FenceProbeError, match="duplicate fields"):
            verify_receipt(changed.encode(), **TARGET)
