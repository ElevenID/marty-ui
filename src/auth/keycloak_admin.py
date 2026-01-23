"""
Keycloak Admin Client

Provides admin operations for Keycloak:
- Get/update user roles
- Get/create organizations
- Add users to organizations
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class KeycloakAdminConfig:
    """Keycloak admin configuration."""
    
    server_url: str
    realm: str
    admin_client_id: str
    admin_client_secret: str
    
    @classmethod
    def from_env(cls) -> KeycloakAdminConfig:
        """Create config from environment variables."""
        return cls(
            server_url=os.environ.get("KEYCLOAK_URL", "http://keycloak:8080"),
            realm=os.environ.get("KEYCLOAK_REALM", "marty"),
            admin_client_id=os.environ.get("KEYCLOAK_ADMIN_CLIENT_ID", "admin-cli"),
            admin_client_secret=os.environ.get("KEYCLOAK_ADMIN_CLIENT_SECRET", ""),
        )


class KeycloakAdminClient:
    """
    Keycloak Admin API client.
    
    Uses service account authentication via client credentials.
    """
    
    def __init__(self, config: KeycloakAdminConfig | None = None):
        self.config = config or KeycloakAdminConfig.from_env()
        self._access_token: str | None = None
        self._token_expires_at: float = 0
        self._http_client = httpx.AsyncClient(timeout=30.0)
    
    @property
    def _base_url(self) -> str:
        """Base URL for admin API."""
        return f"{self.config.server_url}/admin/realms/{self.config.realm}"
    
    def _clear_token(self) -> None:
        """Clear cached token to force refresh."""
        self._access_token = None
        self._token_expires_at = 0
    
    async def _get_admin_token(self) -> str:
        """Get admin access token using client credentials."""
        import time
        
        # Check if token is still valid (with 30 second buffer)
        if self._access_token and time.time() < (self._token_expires_at - 30):
            return self._access_token
        
        # Clear expired token
        self._clear_token()
        
        token_url = f"{self.config.server_url}/realms/{self.config.realm}/protocol/openid-connect/token"
        
        # Try client credentials first
        if self.config.admin_client_secret:
            response = await self._http_client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.admin_client_id,
                    "client_secret": self.config.admin_client_secret,
                },
            )
        else:
            # Fall back to master realm admin user
            admin_user = os.environ.get("KEYCLOAK_ADMIN", "admin")
            admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
            
            # Get token from master realm
            master_token_url = f"{self.config.server_url}/realms/master/protocol/openid-connect/token"
            response = await self._http_client.post(
                master_token_url,
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": admin_user,
                    "password": admin_pass,
                },
            )
        
        if response.status_code != 200:
            logger.error(f"Failed to get admin token: {response.text}")
            raise Exception(f"Failed to authenticate with Keycloak: {response.status_code}")
        
        token_data = response.json()
        self._access_token = token_data["access_token"]
        # Store token expiry time
        expires_in = token_data.get("expires_in", 300)  # Default 5 min
        self._token_expires_at = time.time() + expires_in
        return self._access_token
    
    async def _request(
        self, 
        method: str, 
        path: str, 
        json: Any | None = None,
        params: dict | None = None,
        content: str | None = None,
        content_type: str | None = None,
    ) -> httpx.Response:
        """Make authenticated request to Keycloak admin API."""
        token = await self._get_admin_token()
        
        url = f"{self._base_url}{path}"
        headers = {"Authorization": f"Bearer {token}"}
        
        # Handle raw content vs JSON
        if content is not None:
            headers["Content-Type"] = content_type or "application/json"
            response = await self._http_client.request(
                method, 
                url, 
                headers=headers, 
                content=content,
                params=params,
            )
        else:
            response = await self._http_client.request(
                method, 
                url, 
                headers=headers, 
                json=json,
                params=params,
            )
        
        # If 401, token may have expired - clear and retry once
        if response.status_code == 401:
            logger.warning("Got 401 from Keycloak admin API, refreshing token...")
            self._clear_token()
            token = await self._get_admin_token()
            headers = {"Authorization": f"Bearer {token}"}
            if content is not None:
                headers["Content-Type"] = content_type or "application/json"
                response = await self._http_client.request(
                    method, 
                    url, 
                    headers=headers, 
                    content=content,
                    params=params,
                )
            else:
                response = await self._http_client.request(
                    method, 
                    url, 
                    headers=headers, 
                    json=json,
                    params=params,
                )
        
        return response
    
    # =========================================================================
    # User Operations
    # =========================================================================
    
    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Get user by ID."""
        response = await self._request("GET", f"/users/{user_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    
    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Get user's realm roles."""
        response = await self._request("GET", f"/users/{user_id}/role-mappings/realm")
        response.raise_for_status()
        return response.json()
    
    async def add_user_role(self, user_id: str, role_name: str) -> None:
        """Add a realm role to a user."""
        # First, get the role to get its ID
        role = await self.get_realm_role(role_name)
        if not role:
            raise ValueError(f"Role '{role_name}' not found")
        
        response = await self._request(
            "POST",
            f"/users/{user_id}/role-mappings/realm",
            json=[{"id": role["id"], "name": role["name"]}],
        )
        response.raise_for_status()
        logger.info(f"Added role '{role_name}' to user {user_id}")
    
    async def remove_user_role(self, user_id: str, role_name: str) -> None:
        """Remove a realm role from a user."""
        role = await self.get_realm_role(role_name)
        if not role:
            return  # Role doesn't exist, nothing to remove
        
        response = await self._request(
            "DELETE",
            f"/users/{user_id}/role-mappings/realm",
            json=[{"id": role["id"], "name": role["name"]}],
        )
        response.raise_for_status()
        logger.info(f"Removed role '{role_name}' from user {user_id}")
    
    async def update_user_attributes(
        self, 
        user_id: str, 
        attributes: dict[str, list[str]],
    ) -> None:
        """Update user attributes.
        
        Keycloak requires the full user representation when updating via PUT,
        so we fetch the current user, merge the new attributes, and send back
        the complete user data.
        """
        # Get current user to preserve other fields
        user = await self.get_user(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")
        
        # Merge new attributes with existing
        current_attrs = user.get("attributes", {})
        current_attrs.update(attributes)
        user["attributes"] = current_attrs
        
        # Send full user representation back (Keycloak requires this)
        response = await self._request(
            "PUT",
            f"/users/{user_id}",
            json=user,
        )
        response.raise_for_status()
        logger.info(f"Updated attributes for user {user_id}")
    
    async def get_realm_role(self, role_name: str) -> dict[str, Any] | None:
        """Get a realm role by name."""
        response = await self._request("GET", f"/roles/{role_name}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    
    # =========================================================================
    # Organization Operations (Keycloak 25+ Organizations feature)
    # =========================================================================
    
    async def list_organizations(self) -> list[dict[str, Any]]:
        """List all organizations."""
        response = await self._request("GET", "/organizations")
        if response.status_code == 404:
            # Organizations feature might not be enabled
            return []
        response.raise_for_status()
        return response.json()
    
    async def get_organization(self, org_id: str) -> dict[str, Any] | None:
        """Get organization by ID."""
        response = await self._request("GET", f"/organizations/{org_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    
    async def check_organization_name_available(self, name: str) -> bool:
        """Check if an organization name is available.
        
        Returns True if the name is available, False if already taken.
        """
        orgs = await self.list_organizations()
        name_lower = name.lower().strip()
        
        for org in orgs:
            if org.get("name", "").lower().strip() == name_lower:
                return False
        
        return True
    
    async def create_organization(
        self,
        name: str,
        description: str | None = None,
        domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new organization.
        
        Note: Keycloak 25+ requires at least one domain for organizations.
        If no domains are provided, a default domain is auto-generated from the org name.
        """
        import re
        
        # Keycloak 25+ requires at least one domain
        # Auto-generate from org name if not provided
        if not domains:
            # Convert name to valid domain format: lowercase, replace spaces/special chars
            slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
            domains = [f"{slug}.marty.local"]
        
        org_data = {
            "name": name,
            "enabled": True,
            "domains": [{"name": d, "verified": False} for d in domains],
        }
        if description:
            org_data["description"] = description
        
        response = await self._request("POST", "/organizations", json=org_data)
        
        if response.status_code == 201:
            # Get the created org from Location header
            location = response.headers.get("Location", "")
            org_id = location.split("/")[-1] if location else None
            if org_id:
                return await self.get_organization(org_id) or {"id": org_id, "name": name}
            return {"name": name}
        
        response.raise_for_status()
        return response.json()
    
    async def add_user_to_organization(
        self,
        org_id: str,
        user_id: str,
    ) -> None:
        """Add a user to an organization.
        
        Note: Keycloak 25 Organizations API expects the user ID as a raw string body
        (not JSON-encoded). This is an unusual API design but documented in Keycloak source.
        """
        # Keycloak expects raw string, not JSON-encoded string
        response = await self._request(
            "POST",
            f"/organizations/{org_id}/members",
            content=user_id,  # Raw string, not JSON
        )
        
        if response.status_code == 409:
            logger.info(f"User {user_id} already member of org {org_id}")
            return
        
        response.raise_for_status()
        logger.info(f"Added user {user_id} to organization {org_id}")
    
    async def get_organization_members(self, org_id: str) -> list[dict[str, Any]]:
        """Get all members of an organization."""
        response = await self._request("GET", f"/organizations/{org_id}/members")
        response.raise_for_status()
        return response.json()
    
    async def get_user_organizations(self, user_id: str) -> list[dict[str, Any]]:
        """Get organizations a user belongs to."""
        # Keycloak doesn't have a direct endpoint for this, 
        # so we need to check each org
        orgs = await self.list_organizations()
        user_orgs = []
        
        for org in orgs:
            members = await self.get_organization_members(org["id"])
            if any(m.get("id") == user_id for m in members):
                user_orgs.append(org)
        
        return user_orgs
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http_client.aclose()


# Singleton instance
_admin_client: KeycloakAdminClient | None = None


async def get_keycloak_admin() -> KeycloakAdminClient:
    """Get or create Keycloak admin client singleton."""
    global _admin_client
    if _admin_client is None:
        _admin_client = KeycloakAdminClient()
    return _admin_client
