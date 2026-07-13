from __future__ import annotations

import logging
import os

import httpx

from ...domain.entities import AuthenticatedUser
from .user_provisioning_adapter import MARTY_ORG_ID

logger = logging.getLogger(__name__)

_DEFAULT_APPLICANT_SERVICE_URL = "http://applicant:8006"


def apply_credential_login_defaults(user: AuthenticatedUser) -> AuthenticatedUser:
    """Ensure credential-login users land with the default Marty org context."""
    if "canvas_lti_learner" in (user.roles or []):
        return user
    if not user.organization_id:
        user.organization_id = os.environ.get("MARTY_ORG_ID", MARTY_ORG_ID)
    return user


class ApplicantProfileProvisioningAdapter:
    """Provision an applicant-service profile for credential-login users."""

    def __init__(
        self,
        service_url: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        resolved_url = service_url or os.environ.get("APPLICANT_SERVICE_URL") or _DEFAULT_APPLICANT_SERVICE_URL
        self._service_url = resolved_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds)

    async def ensure_applicant_profile(self, user: AuthenticatedUser) -> str | None:
        apply_credential_login_defaults(user)

        if not user.user_id or not user.email or not user.organization_id:
            return user.applicant_id

        payload = {
            "organization_id": user.organization_id,
            "email": user.email,
            "given_name": user.given_name,
            "family_name": user.family_name,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.patch(
                    f"{self._service_url}/v1/me/applicant-profile",
                    json=payload,
                    headers={
                        "X-User-Id": user.user_id,
                        "X-User-Email": user.email,
                        "X-Organization-ID": user.organization_id,
                    },
                )
                response.raise_for_status()
        except Exception as exc:
            logger.warning(
                "Failed to provision applicant profile for credential login user %s: %s",
                user.email,
                exc,
            )
            return user.applicant_id

        data = response.json()
        if isinstance(data, dict):
            applicant_id = data.get("id")
            if isinstance(applicant_id, str) and applicant_id:
                return applicant_id

        return user.applicant_id

    async def __call__(self, user: AuthenticatedUser) -> str | None:
        return await self.ensure_applicant_profile(user)
