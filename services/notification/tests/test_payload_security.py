"""Marty-owned tests for notification payload minimization."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from services.notification import main as notification


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(notification.router)
    notification._repo = notification.InMemoryNotificationRepository()
    return TestClient(app)


def _send(
    data: dict[str, object],
    *,
    title: str = "Lifecycle update",
    body: str = "Open the portal for details.",
) -> object:
    return _client().post(
        "/v1/notifications/send",
        json={
            "organization_id": "org-1",
            "title": title,
            "body": body,
            "event_type": "credential.offered",
            "data": data,
            "target": {
                "email_addresses": ["holder@example.com"],
                "channels": ["EMAIL"],
            },
        },
    )


@pytest.mark.parametrize(
    "data",
    [
        {"credential": {"iss": "https://issuer.example"}},
        {"nested": {"vp_token": "opaque"}},
        {"private_key": "not-a-real-key"},
        {"payload": "opaque-mdoc-or-credential"},
        {
            "reference": (
                "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij0123456789"
            )
        },
    ],
)
def test_send_rejects_raw_or_opaque_credential_material(
    data: dict[str, object],
) -> None:
    response = _send(data)

    assert response.status_code == 422
    assert "protected credential material" in response.text


def test_send_enforces_the_protocol_four_kibibyte_data_limit() -> None:
    response = _send({"safe_message": "x" * 4096})

    assert response.status_code == 422
    assert "4 KB protocol limit" in response.text


@pytest.mark.parametrize(
    ("title", "body", "expected"),
    [
        ("x" * 257, "safe", "256 character"),
        ("safe", "x" * 2049, "2048 character"),
        (
            "safe",
            ("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij0123456789"),
            "protected credential material",
        ),
        (
            "safe",
            '{"credentialSubject":{"name":"Private"},"proof":"opaque"}',
            "protected credential material",
        ),
    ],
)
def test_send_rejects_oversized_or_credential_bearing_text(
    title: str, body: str, expected: str
) -> None:
    response = _send({}, title=title, body=body)

    assert response.status_code == 422
    assert expected in response.text


def test_send_accepts_offer_uri_and_minimized_lifecycle_metadata() -> None:
    data = {
        "offer_uri": (
            "openid-credential-offer://?credential_offer_uri="
            "https://issuer.example/offers/offer-1"
        ),
        "credential_type": "MemberCredential",
        "application_id": "application-1",
    }

    response = _send(data)

    assert response.status_code == 200, response.text
    assert response.json()["data"] == data


def test_internal_application_event_accepts_only_the_minimized_projection() -> None:
    event = notification.EventIngestRequest(
        event_id="event-1",
        event_type="application.approved",
        aggregate_id="application-1",
        aggregate_type="application",
        organization_id="org-1",
        data={
            "applicant_id": "applicant-1",
            "application_id": "application-1",
            "credential_template_id": "template-1",
            "status": "approved",
        },
    )

    assert event.data == {
        "applicant_id": "applicant-1",
        "application_id": "application-1",
        "credential_template_id": "template-1",
        "status": "approved",
    }


@pytest.mark.parametrize(
    "extra_data",
    [
        {"email": "holder@example.com"},
        {"given_name": "Private"},
        {"reviewer_notes": "Contains case details"},
        {"rejection_reason": "Free-form personal information"},
        {"vetting_level": "enhanced"},
    ],
)
def test_internal_application_event_rejects_noncontract_personal_data(
    extra_data: dict[str, str],
) -> None:
    with pytest.raises(
        ValidationError,
        match="fields outside the minimized event contract",
    ):
        notification.EventIngestRequest(
            event_id="event-1",
            event_type="application.approved",
            aggregate_id="application-1",
            aggregate_type="application",
            organization_id="org-1",
            data={"application_id": "application-1", **extra_data},
        )


def test_internal_event_rejects_unversioned_custom_fan_out() -> None:
    with pytest.raises(
        ValidationError,
        match="event_type is not supported for notification fan-out",
    ):
        notification.EventIngestRequest(
            event_id="event-1",
            event_type="custom.unbounded",
            aggregate_id="aggregate-1",
            aggregate_type="custom",
            organization_id="org-1",
            data={},
        )
