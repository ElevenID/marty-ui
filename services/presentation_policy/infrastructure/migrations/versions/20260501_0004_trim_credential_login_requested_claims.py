"""Trim credential-login requested claims to email only.

Existing credential-login presentation policies asked wallets to disclose
organisation and role claims in addition to email. The auth service now
derives organisation and role context from Keycloak, so the wallet request
should disclose only the holder's email.

Revision ID: 20260501_0004
Revises: 20260322_0003
Create Date: 2026-05-01 00:00:00.000000+00:00
"""

from __future__ import annotations

import copy
import json
from typing import Any

from alembic import op
import sqlalchemy as sa


revision = "20260501_0004"
down_revision = "20260322_0003"
branch_labels = None
depends_on = None


NOW = "2026-05-01T00:00:00+00:00"

LEGACY_DISPLAY_PURPOSE = (
    "Verify your membership credential to log in without a password. "
    "Only your email, organisation, and role will be shared."
)

EMAIL_ONLY_DISPLAY_PURPOSE = (
    "Verify your membership credential to log in without a password. "
    "Only your email will be shared."
)

EMAIL_ONLY_REQUESTED_CLAIMS = [
    {
        "claim_name": "email",
        "display_name": "Email Address",
        "purpose": "Identify your account",
        "required": True,
        "selective_disclosure": True,
        "accept_derived": False,
        "intent_to_retain": False,
        "constraints": [],
    }
]

LEGACY_REQUESTED_CLAIMS = [
    {
        "claim_name": "email",
        "display_name": "Email Address",
        "purpose": "Identify your account",
        "required": True,
        "selective_disclosure": True,
        "accept_derived": False,
        "intent_to_retain": False,
        "constraints": [],
    },
    {
        "claim_name": "organization_id",
        "display_name": "Organisation ID",
        "purpose": "Confirm your organisation membership",
        "required": True,
        "selective_disclosure": True,
        "accept_derived": False,
        "intent_to_retain": False,
        "constraints": [],
    },
    {
        "claim_name": "role",
        "display_name": "Role",
        "purpose": "Determine your access level",
        "required": True,
        "selective_disclosure": True,
        "accept_derived": False,
        "intent_to_retain": False,
        "constraints": [
            {
                "constraint_type": "in_set",
                "value": ["applicant", "vendor", "administrator"],
            }
        ],
    },
    {
        "claim_name": "given_name",
        "display_name": "First Name",
        "purpose": "Personalise your session",
        "required": False,
        "selective_disclosure": True,
        "accept_derived": False,
        "intent_to_retain": False,
        "constraints": [],
    },
    {
        "claim_name": "family_name",
        "display_name": "Last Name",
        "purpose": "Personalise your session",
        "required": False,
        "selective_disclosure": True,
        "accept_derived": False,
        "intent_to_retain": False,
        "constraints": [],
    },
]

POLICY_UPDATES = {
    "50000000-0000-0000-0000-000000000001": {
        "description": (
            "Credential-based login policy. Requests only email from a "
            "MemberCredential. Organisation and role context are resolved "
            "from Keycloak during login."
        ),
        "legacy_description": (
            "Credential-based login policy. Requests email, organisation, "
            "and role from a MemberCredential to authenticate a holder "
            "without requiring a password."
        ),
    },
    "50000000-0000-0000-0000-000000000002": {
        "description": (
            "Marty organisation credential-based login policy (SD-JWT format). "
            "Requests only email from a MemberCredential. Organisation and "
            "role context are resolved from Keycloak during login."
        ),
        "legacy_description": (
            "Marty organisation credential-based login policy (SD-JWT format). "
            "Requests email, organisation, and role from a MemberCredential "
            "to authenticate a holder without requiring a password."
        ),
    },
    "50000000-0000-0000-0000-000000000003": {
        "description": (
            "Marty organisation credential-based login policy (mDoc format). "
            "Requests only email from a Membership ID (mDoc) credential. "
            "Organisation and role context are resolved from Keycloak during login."
        ),
        "legacy_description": (
            "Marty organisation credential-based login policy (mDoc format). "
            "Requests email, organisation, and role from a Membership ID (mDoc) "
            "credential to authenticate a holder without requiring a password."
        ),
    },
}


def _coerce_json_value(raw_value: Any, default: Any) -> Any:
    if raw_value in (None, ""):
        return copy.deepcopy(default)
    if isinstance(raw_value, (dict, list)):
        return copy.deepcopy(raw_value)
    if isinstance(raw_value, (bytes, bytearray)):
        raw_value = raw_value.decode("utf-8")
    if isinstance(raw_value, str):
        return json.loads(raw_value)
    return copy.deepcopy(default)


def _rewrite_requirements(raw_requirements: str | None, requested_claims: list[dict[str, object]]) -> str:
    requirements = _coerce_json_value(raw_requirements, [])
    updated_requirements: list[dict[str, object]] = []
    for requirement in requirements:
        if not isinstance(requirement, dict):
            continue
        updated_requirement = dict(requirement)
        updated_requirement["requested_claims"] = copy.deepcopy(requested_claims)
        updated_requirements.append(updated_requirement)
    return json.dumps(updated_requirements)


def _rewrite_display_metadata(raw_display_metadata: str | None, purpose: str) -> str:
    display_metadata = _coerce_json_value(raw_display_metadata, {})
    if not isinstance(display_metadata, dict):
        display_metadata = {}
    updated_display_metadata = dict(display_metadata)
    updated_display_metadata["purpose"] = purpose
    return json.dumps(updated_display_metadata)


def _apply_updates(*, requested_claims: list[dict[str, object]], purpose: str, description_key: str) -> None:
    connection = op.get_bind()

    for policy_id, description_payload in POLICY_UPDATES.items():
        existing = connection.execute(
            sa.text(
                """
                SELECT id, description, display_metadata, credential_requirements, version
                FROM presentation_policy_service.presentation_policies
                WHERE id = :id
                """
            ),
            {"id": policy_id},
        ).fetchone()

        if existing is None:
            continue

        connection.execute(
            sa.text(
                """
                UPDATE presentation_policy_service.presentation_policies
                SET description = :description,
                    display_metadata = :display_metadata,
                    credential_requirements = :credential_requirements,
                    version = :version,
                    updated_at = :updated_at
                WHERE id = :id
                """
            ),
            {
                "id": policy_id,
                "description": description_payload[description_key],
                "display_metadata": _rewrite_display_metadata(existing.display_metadata, purpose),
                "credential_requirements": _rewrite_requirements(
                    existing.credential_requirements,
                    requested_claims,
                ),
                "version": (existing.version or 1) + 1,
                "updated_at": NOW,
            },
        )


def upgrade() -> None:
    _apply_updates(
        requested_claims=EMAIL_ONLY_REQUESTED_CLAIMS,
        purpose=EMAIL_ONLY_DISPLAY_PURPOSE,
        description_key="description",
    )


def downgrade() -> None:
    _apply_updates(
        requested_claims=LEGACY_REQUESTED_CLAIMS,
        purpose=LEGACY_DISPLAY_PURPOSE,
        description_key="legacy_description",
    )