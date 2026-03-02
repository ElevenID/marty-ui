"""
Keycloak Admin & Token-Exchange Adapter

Provides two capabilities needed for credential-based login:

1. **JIT user provisioning** – ensure a Keycloak user exists for the
   verified identity (looked up by email; created if absent).

2. **Token exchange** – obtain a short-lived KC ``id_token`` + ``refresh_token``
   for that user so the browser session mirrors a regular OIDC login
   (enables KC SSO logout, KC-issued JWT introspection, etc.).

Token exchange in Keycloak requires:
  - ``marty-api`` client: ``directAccessGrantsEnabled: true``,
    ``authorizationServicesEnabled: true``, ``bearerOnly: false``
  - The realm-level token-exchange fine-grained permission enabled
    (Admin → Clients → marty-api → Permissions → token-exchange → ON,
    then grant the marty-api service account the ``token-exchange``
    permission on the ``marty-ui`` client).

When KC is unreachable or not configured, all methods degrade gracefully
and return ``None``; the caller falls back to a session without KC tokens.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class KeycloakAdminAdapter:
    """
    Thin async wrapper around the Keycloak Admin REST API and
    token endpoint for use during credential-based login.
    """

    def __init__(
        self,
        admin_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        timeout: float = 8.0,
    ) -> None:
        self._admin_url = admin_url.rstrip("/")
        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._token_url = f"{self._admin_url}/realms/{realm}/protocol/openid-connect/token"
        self._admin_base = f"{self._admin_url}/admin/realms/{realm}"

    # -------------------------------------------------------------------------
    # Service-account token
    # -------------------------------------------------------------------------

    async def _get_service_account_token(self) -> str | None:
        """Obtain an access token for the marty-api service account."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                )
                resp.raise_for_status()
                return resp.json()["access_token"]
        except Exception as exc:
            logger.warning(f"KC service-account auth failed: {exc}")
            return None

    # -------------------------------------------------------------------------
    # User management
    # -------------------------------------------------------------------------

    async def get_or_create_user(
        self,
        email: str,
        given_name: str | None = None,
        family_name: str | None = None,
        role: str = "applicant",
    ) -> str | None:
        """
        Return the Keycloak user ID for *email*, creating the user if absent.

        Returns ``None`` when KC is unavailable or the operation fails.
        """
        sa_token = await self._get_service_account_token()
        if not sa_token:
            return None

        headers = {"Authorization": f"Bearer {sa_token}"}

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # Search for existing user
                r = await client.get(
                    f"{self._admin_base}/users",
                    params={"email": email, "exact": "true"},
                    headers=headers,
                )
                r.raise_for_status()
                results: list[dict[str, Any]] = r.json()

                if results:
                    user_id: str = results[0]["id"]
                    logger.debug(f"KC user found for {email}: {user_id}")
                    return user_id

                # Create user
                create_payload: dict[str, Any] = {
                    "email": email,
                    "emailVerified": True,
                    "enabled": True,
                    "attributes": {
                        "user_type": [role],
                    },
                }
                if given_name:
                    create_payload["firstName"] = given_name
                if family_name:
                    create_payload["lastName"] = family_name

                c = await client.post(
                    f"{self._admin_base}/users",
                    json=create_payload,
                    headers=headers,
                )
                c.raise_for_status()

                # KC returns 201 with Location header containing the new user ID
                location: str = c.headers.get("location", "")
                if location:
                    new_user_id = location.rstrip("/").rsplit("/", 1)[-1]
                    logger.info(f"KC user created for {email}: {new_user_id}")
                    return new_user_id

                logger.warning(f"KC user creation succeeded but no Location header for {email}")
                return None

        except Exception as exc:
            logger.warning(f"KC user get/create failed for {email}: {exc}")
            return None

    # -------------------------------------------------------------------------
    # Token exchange
    # -------------------------------------------------------------------------

    async def exchange_token_for_user(
        self,
        kc_user_id: str,
        audience: str = "marty-ui",
    ) -> dict[str, str] | None:
        """
        Perform an RFC 8693 token exchange to obtain KC-issued tokens for
        a Keycloak user identified by *kc_user_id*.

        Returns a dict with ``id_token`` and ``refresh_token``, or ``None``
        when the exchange fails or KC does not have token exchange enabled.
        """
        sa_token = await self._get_service_account_token()
        if not sa_token:
            return None

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._token_url,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "subject_token": sa_token,
                        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "requested_subject": kc_user_id,
                        "audience": audience,
                        "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
                    },
                )
                if resp.status_code == 400:
                    # Token exchange is not enabled or not permitted  — soft failure
                    logger.info(
                        f"KC token exchange not available (400): {resp.text[:200]}"
                    )
                    return None
                resp.raise_for_status()

                tokens = resp.json()
                return {
                    "id_token": tokens.get("id_token", ""),
                    "refresh_token": tokens.get("refresh_token", ""),
                    "access_token": tokens.get("access_token", ""),
                }

        except Exception as exc:
            logger.warning(f"KC token exchange failed for user {kc_user_id}: {exc}")
            return None


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------

def build_keycloak_admin_adapter() -> KeycloakAdminAdapter | None:
    """
    Build a :class:`KeycloakAdminAdapter` from environment variables.

    Returns ``None`` if the required env vars are not set, indicating that
    KC integration is disabled and sessions will be created without KC tokens.
    """
    admin_url = os.environ.get("KEYCLOAK_ADMIN_URL", "")
    client_id = os.environ.get("MARTY_API_CLIENT_ID", "")
    client_secret = os.environ.get("MARTY_API_CLIENT_SECRET", "")
    realm = os.environ.get("KEYCLOAK_REALM", "11id")

    if not (admin_url and client_id and client_secret):
        logger.info(
            "KC admin adapter disabled "
            "(set KEYCLOAK_ADMIN_URL, MARTY_API_CLIENT_ID, MARTY_API_CLIENT_SECRET)"
        )
        return None

    return KeycloakAdminAdapter(
        admin_url=admin_url,
        realm=realm,
        client_id=client_id,
        client_secret=client_secret,
    )
