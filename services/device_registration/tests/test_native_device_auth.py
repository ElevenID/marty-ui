from __future__ import annotations

import json
from pathlib import Path

import pytest

from common.native_backend import NativeBackendUnavailable, NativeOperationError
from services.device_registration import native
from services.device_registration.challenges import ChallengeRecord

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "device_auth.json"


def test_shared_challenge_vectors_use_only_the_native_builder() -> None:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert vectors["schema_version"] == 1
    for case in vectors["challenge_cases"]:
        record = ChallengeRecord(**case["challenge"])
        assert record.encoded_message() == case["expected_message_base64url"], case[
            "name"
        ]


def test_missing_native_backend_fails_without_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)

    def unavailable(*, required_capability: str | None = None):
        del required_capability
        raise NativeBackendUnavailable("native backend unavailable")

    monkeypatch.setattr(native, "load_marty_rs", unavailable)
    with pytest.raises(NativeBackendUnavailable, match="native backend unavailable"):
        native.inspect_public_key("AA")


def test_native_diagnostics_require_device_auth_capability() -> None:
    diagnostics = native.initialize_device_auth_backend()
    assert diagnostics["available"] is True
    assert diagnostics["backend"] == "_marty_rs"
    assert "device_authentication" in diagnostics["capabilities"]


def test_malformed_native_decision_is_not_treated_as_a_denial() -> None:
    with pytest.raises(NativeOperationError, match="decision"):
        native._decision({}, allowed_codes={"DENIED"})
