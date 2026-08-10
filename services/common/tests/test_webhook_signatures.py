import pytest

from common.webhook_signatures import (
    AUTH_CALLBACK_AUDIENCE,
    sign_event,
    verify_event_signature,
)


def test_event_signature_binds_headers_and_payload() -> None:
    payload = {"flow_instance_id": "flow-1", "decision": "allow"}
    signature = sign_event(
        "shared-secret-at-least-32-bytes-long",
        audience=AUTH_CALLBACK_AUDIENCE,
        event="flow.verification_completed",
        event_id="flow-1",
        timestamp="2026-08-08T16:00:00+00:00",
        payload=payload,
    )

    assert verify_event_signature(
        signature,
        "shared-secret-at-least-32-bytes-long",
        audience=AUTH_CALLBACK_AUDIENCE,
        event="flow.verification_completed",
        event_id="flow-1",
        timestamp="2026-08-08T16:00:00+00:00",
        payload=payload,
    )
    assert not verify_event_signature(
        signature,
        "shared-secret-at-least-32-bytes-long",
        audience=AUTH_CALLBACK_AUDIENCE,
        event="flow.verification_completed",
        event_id="flow-2",
        timestamp="2026-08-08T16:00:00+00:00",
        payload=payload,
    )
    assert not verify_event_signature(
        signature,
        "shared-secret-at-least-32-bytes-long",
        audience="another-service",
        event="flow.verification_completed",
        event_id="flow-1",
        timestamp="2026-08-08T16:00:00+00:00",
        payload=payload,
    )


def test_event_signature_rejects_weak_shared_secrets() -> None:
    event = {
        "audience": AUTH_CALLBACK_AUDIENCE,
        "event": "flow.verification_completed",
        "event_id": "flow-1",
        "timestamp": "2026-08-08T16:00:00+00:00",
        "payload": {"flow_instance_id": "flow-1"},
    }

    with pytest.raises(ValueError, match="at least 32 bytes"):
        sign_event("weak-secret", **event)
    assert not verify_event_signature("sha256=invalid", "weak-secret", **event)
