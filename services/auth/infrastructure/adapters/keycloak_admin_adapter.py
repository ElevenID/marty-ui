"""
Keycloak Admin & Token-Exchange Adapter

Provides two capabilities needed for credential-based login:

1. **User lookup / optional JIT provisioning** – credential login uses strict
    existing-user lookup; legacy callers may still use explicit get-or-create.

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
from urllib.parse import urlparse, urlunparse

import httpx

from ...domain.entities import OIDCUserInfo

logger = logging.getLogger(__name__)


def _first_attribute(attributes: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = attributes.get(name)
        if isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, str) and first:
                return first
        if isinstance(value, str) and value:
            return value
    return None


def _attribute_strings(attributes: dict[str, Any], *names: str) -> list[str]:
    values: list[str] = []
    for name in names:
        raw_value = attributes.get(name)
        candidates = raw_value if isinstance(raw_value, list) else [raw_value]
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate:
                continue
            parsed = _try_parse_json(candidate)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item and item not in values:
                        values.append(item)
                continue
            for part in candidate.split(","):
                role = part.strip()
                if role and role not in values:
                    values.append(role)
    return values


def _try_parse_json(value: str) -> Any:
    try:
        import json

        return json.loads(value)
    except Exception:
        return None


def _normalize_keycloak_organization_claim(raw_value: Any) -> dict[str, Any] | None:
    if not raw_value:
        return None

    if isinstance(raw_value, str):
        parsed = _try_parse_json(raw_value)
        raw_value = parsed if parsed is not None else raw_value

    if isinstance(raw_value, dict):
        if isinstance(raw_value.get("organizations"), list):
            return _normalize_keycloak_organization_claim(raw_value["organizations"])
        if any(isinstance(value, dict) for value in raw_value.values()):
            return raw_value
        org_id = raw_value.get("id") or raw_value.get("alias") or raw_value.get("name")
        if isinstance(org_id, str) and org_id:
            display_name = (
                raw_value.get("display_name")
                or raw_value.get("displayName")
                or raw_value.get("name")
                or raw_value.get("alias")
            )
            return {
                org_id: {
                    "name": display_name or org_id,
                    "display_name": display_name or org_id,
                }
            }
        return None

    if isinstance(raw_value, list):
        organizations: dict[str, Any] = {}
        for item in raw_value:
            if isinstance(item, str):
                parsed = _try_parse_json(item)
                item = parsed if parsed is not None else {"id": item, "name": item}
            if not isinstance(item, dict):
                continue
            org_id = item.get("id") or item.get("alias") or item.get("name")
            if not isinstance(org_id, str) or not org_id:
                continue
            display_name = (
                item.get("display_name")
                or item.get("displayName")
                or item.get("name")
                or item.get("alias")
                or org_id
            )
            organizations[org_id] = {
                "name": display_name,
                "display_name": display_name,
            }
        return organizations or None

    return None


def _merge_roles(*role_sets: list[str]) -> list[str]:
    roles: list[str] = []
    for role_set in role_sets:
        for role in role_set:
            if role and role not in roles:
                roles.append(role)
    return roles


def merge_oidc_user_info(
    primary: OIDCUserInfo | None,
    secondary: OIDCUserInfo | None,
) -> OIDCUserInfo | None:
    """Merge token-derived and admin-derived Keycloak user context."""
    if primary is None:
        return secondary
    if secondary is None:
        return primary

    return OIDCUserInfo(
        sub=primary.sub or secondary.sub,
        email=primary.email or secondary.email,
        email_verified=primary.email_verified or secondary.email_verified,
        name=primary.name or secondary.name,
        given_name=primary.given_name or secondary.given_name,
        family_name=primary.family_name or secondary.family_name,
        preferred_username=primary.preferred_username or secondary.preferred_username,
        picture=primary.picture or secondary.picture,
        locale=primary.locale or secondary.locale,
        organization_id=primary.organization_id or secondary.organization_id,
        organization_name=primary.organization_name or secondary.organization_name,
        organization=primary.organization or secondary.organization,
        roles=_merge_roles(primary.roles, secondary.roles),
    )


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
        token_exchange_enabled: bool | None = None,
    ) -> None:
        self._admin_url = admin_url.rstrip("/")
        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._token_exchange_enabled = (
            token_exchange_enabled
            if token_exchange_enabled is not None
            else os.environ.get("KEYCLOAK_TOKEN_EXCHANGE_ENABLED", "false").lower() in {"1", "true", "yes"}
        )
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
        username: str | None = None,
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
                results: list[dict[str, Any]] = []

                if email:
                    r = await client.get(
                        f"{self._admin_base}/users",
                        params={"email": email, "exact": "true"},
                        headers=headers,
                    )
                    r.raise_for_status()
                    results = r.json()

                if not results and username:
                    r = await client.get(
                        f"{self._admin_base}/users",
                        params={"username": username, "exact": "true"},
                        headers=headers,
                    )
                    r.raise_for_status()
                    results = r.json()

                if results:
                    user_id: str = results[0]["id"]
                    logger.debug(f"KC user found for {email[:3]}***: {user_id}")
                    return user_id

                # Create user
                create_payload: dict[str, Any] = {
                    "username": username or email,
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
                    logger.info(f"KC user created for {email[:3]}***: {new_user_id}")
                    return new_user_id

                logger.warning(f"KC user creation succeeded but no Location header for {email[:3]}***")
                return None

        except Exception as exc:
            logger.warning(f"KC user get/create failed for {email[:3]}***: {exc}")
            return None

    async def find_existing_user(
        self,
        email: str,
        username: str | None = None,
    ) -> dict[str, Any] | None:
        """Find an existing Keycloak user by exact email or username.

        Unlike ``get_or_create_user``, this method never creates users. It is
        the safe path for public credential-login finalization.
        """
        sa_token = await self._get_service_account_token()
        if not sa_token:
            return None

        headers = {"Authorization": f"Bearer {sa_token}"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                if email:
                    resp = await client.get(
                        f"{self._admin_base}/users",
                        params={"email": email, "exact": "true"},
                        headers=headers,
                    )
                    resp.raise_for_status()
                    results = resp.json()
                    if results:
                        return results[0]

                if username:
                    resp = await client.get(
                        f"{self._admin_base}/users",
                        params={"username": username, "exact": "true"},
                        headers=headers,
                    )
                    resp.raise_for_status()
                    results = resp.json()
                    if results:
                        return results[0]
        except Exception as exc:
            logger.warning("KC existing-user lookup failed for %s***: %s", email[:3], exc)
            return None

        return None

    async def get_existing_verified_user_id(
        self,
        email: str,
        username: str | None = None,
    ) -> str | None:
        """Return an existing enabled/email-verified KC user ID for login.

        Returns ``None`` if no user exists. Raises ``ValueError`` when a user is
        found but is disabled, unverified, or does not match the disclosed email.
        """
        profile = await self.find_existing_user(email=email, username=username)
        if not profile:
            return None

        user_id = str(profile.get("id") or "")
        if not user_id:
            raise ValueError("Keycloak user profile is missing id")
        if profile.get("enabled") is False:
            raise ValueError("Keycloak user is disabled")
        if not bool(profile.get("emailVerified", False)):
            raise ValueError("Keycloak user email is not verified")

        profile_email = str(profile.get("email") or "").lower()
        if email and profile_email and profile_email != email.lower():
            raise ValueError("Keycloak user email does not match credential email")

        return user_id

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
        if not self._token_exchange_enabled:
            return None

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

    async def get_user_info(self, kc_user_id: str) -> OIDCUserInfo | None:
        """Read roles and organization context from Keycloak Admin REST.

        This is the fallback used by credential login when RFC 8693 token
        exchange is unavailable.  Badge login trusts the badge for the email
        that identified the user, but Keycloak remains the source of truth for
        roles and organizations.
        """
        sa_token = await self._get_service_account_token()
        if not sa_token:
            return None

        headers = {"Authorization": f"Bearer {sa_token}"}

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                profile_resp = await client.get(
                    f"{self._admin_base}/users/{kc_user_id}",
                    headers=headers,
                )
                profile_resp.raise_for_status()
                profile = profile_resp.json()

                attributes = profile.get("attributes")
                if not isinstance(attributes, dict):
                    attributes = {}

                roles = _attribute_strings(attributes, "roles", "role", "user_type")
                try:
                    mappings_resp = await client.get(
                        f"{self._admin_base}/users/{kc_user_id}/role-mappings",
                        headers=headers,
                    )
                    if mappings_resp.status_code != 404:
                        mappings_resp.raise_for_status()
                        role_mappings = mappings_resp.json()
                        for role in role_mappings.get("realmMappings") or []:
                            name = role.get("name") if isinstance(role, dict) else None
                            if isinstance(name, str) and name and name not in roles:
                                roles.append(name)
                        client_mappings = role_mappings.get("clientMappings") or {}
                        if isinstance(client_mappings, dict):
                            for mapping in client_mappings.values():
                                if not isinstance(mapping, dict):
                                    continue
                                for role in mapping.get("mappings") or []:
                                    name = role.get("name") if isinstance(role, dict) else None
                                    if isinstance(name, str) and name and name not in roles:
                                        roles.append(name)
                except Exception as exc:
                    logger.debug("KC role mapping read failed for %s: %s", kc_user_id, exc)

                organization_claim = _normalize_keycloak_organization_claim(
                    _first_attribute(attributes, "organization", "organizations")
                )
                try:
                    org_resp = await client.get(
                        f"{self._admin_base}/users/{kc_user_id}/organizations",
                        headers=headers,
                    )
                    if org_resp.status_code != 404:
                        org_resp.raise_for_status()
                        admin_org_claim = _normalize_keycloak_organization_claim(org_resp.json())
                        if admin_org_claim:
                            organization_claim = admin_org_claim
                except Exception as exc:
                    logger.debug("KC organization read failed for %s: %s", kc_user_id, exc)

                claims: dict[str, Any] = {
                    "sub": profile.get("id") or kc_user_id,
                    "email": profile.get("email") or _first_attribute(attributes, "email") or "",
                    "email_verified": bool(profile.get("emailVerified", True)),
                    "name": profile.get("name") or _first_attribute(attributes, "name"),
                    "given_name": profile.get("firstName") or _first_attribute(attributes, "given_name"),
                    "family_name": profile.get("lastName") or _first_attribute(attributes, "family_name"),
                    "preferred_username": profile.get("username") or _first_attribute(attributes, "preferred_username", "username"),
                    "roles": roles,
                }
                if organization_claim:
                    claims["organization"] = organization_claim
                else:
                    org_id = _first_attribute(attributes, "organization_id", "org_id")
                    org_name = _first_attribute(attributes, "organization_name", "org_name")
                    if org_id:
                        claims["organization_id"] = org_id
                    if org_name:
                        claims["organization_name"] = org_name

                return OIDCUserInfo.from_claims(claims)
        except Exception as exc:
            logger.warning("KC admin user enrichment failed for %s: %s", kc_user_id, exc)
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
    realm = os.environ.get("KEYCLOAK_REALM", "")

    if not (admin_url and client_id and client_secret):
        logger.info(
            "KC admin adapter disabled "
            "(set KEYCLOAK_ADMIN_URL, MARTY_API_CLIENT_ID, MARTY_API_CLIENT_SECRET)"
        )
        return None

    # Normalize legacy/local URLs so containerized auth can always reach KC.
    # Expected base: http://keycloak:8080 (without /admin suffix).
    parsed = urlparse(admin_url)
    scheme = parsed.scheme or "http"
    hostname = parsed.hostname or ""
    port = parsed.port
    path = (parsed.path or "").rstrip("/")

    if path.endswith("/admin"):
        path = path[:-6]

    if hostname in {"localhost", "127.0.0.1"}:
        hostname = "keycloak"
        # Localhost mappings typically expose 8180 externally, but inside the
        # docker network Keycloak listens on 8080.
        port = 8080

    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    normalized_admin_url = urlunparse((scheme, netloc, path, "", "", "")).rstrip("/")
    if normalized_admin_url != admin_url.rstrip("/"):
        logger.warning(
            "Normalized KEYCLOAK_ADMIN_URL from %s to %s for container reachability",
            admin_url,
            normalized_admin_url,
        )
    admin_url = normalized_admin_url

    return KeycloakAdminAdapter(
        admin_url=admin_url,
        realm=realm,
        client_id=client_id,
        client_secret=client_secret,
    )
