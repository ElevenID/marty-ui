"""
Keycloak OIDC Provider Adapter

Implements OIDCProviderPort for Keycloak authentication.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from ...application.ports import OIDCProviderPort
from ...domain.entities import OIDCUserInfo

logger = logging.getLogger(__name__)


def decode_jwt_claims(token: str | None) -> dict[str, Any]:
    """Decode JWT claims without signature verification."""
    if not token:
        return {}

    parts = token.split(".")
    if len(parts) != 3:
        return {}

    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding

    try:
        claims_json = base64.urlsafe_b64decode(payload).decode("utf-8")
        return json.loads(claims_json)
    except (ValueError, json.JSONDecodeError):
        return {}


def build_oidc_user_info(id_token: str | None = None, access_token: str | None = None) -> OIDCUserInfo:
    """Build OIDC user info from Keycloak-issued ID/access tokens."""
    id_claims = decode_jwt_claims(id_token)
    access_claims = decode_jwt_claims(access_token)

    if not id_claims and not access_claims:
        raise ValueError("Invalid token payload")

    if id_claims:
        return OIDCUserInfo.from_claims(id_claims, access_claims)

    return OIDCUserInfo.from_claims(access_claims)


@dataclass
class OIDCConfig:
    """OIDC configuration for Keycloak."""
    
    issuer_url: str  # Internal URL for server-to-server calls
    client_id: str
    client_secret: str | None = None
    redirect_uri: str = "http://localhost:8001/v1/auth/callback"
    scopes: list[str] | None = None
    external_issuer_url: str | None = None  # External URL for browser redirects
    
    def __post_init__(self) -> None:
        if self.scopes is None:
            self.scopes = ["openid", "email", "profile"]
        # Default external URL to internal URL if not specified
        if self.external_issuer_url is None:
            self.external_issuer_url = self.issuer_url
    
    @property
    def authorization_endpoint(self) -> str:
        # Use external URL for browser redirects
        return f"{self.external_issuer_url}/protocol/openid-connect/auth"
    
    @property
    def registration_endpoint(self) -> str:
        return f"{self.external_issuer_url}/protocol/openid-connect/registrations"
    
    @property
    def token_endpoint(self) -> str:
        # Use internal URL for server-to-server token exchange
        return f"{self.issuer_url}/protocol/openid-connect/token"
    
    @property
    def logout_endpoint(self) -> str:
        # Use external URL for browser redirects
        return f"{self.external_issuer_url}/protocol/openid-connect/logout"


class KeycloakOIDCAdapter(OIDCProviderPort):
    """
    Keycloak OIDC provider adapter.
    
    Implements the OIDCProviderPort for authentication with Keycloak
    using the authorization code flow with PKCE.
    """
    
    def __init__(self, config: OIDCConfig):
        self.config = config
    
    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str | None = None,
    ) -> str:
        """Build Keycloak authorization URL with PKCE."""
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            # Use select_account to allow switching users, or consent to force new auth session
            "prompt": "consent login",  # Force re-authentication and consent
        }
        
        return f"{self.config.authorization_endpoint}?{urlencode(params)}"
    
    def get_registration_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str | None = None,
    ) -> str:
        """Build Keycloak registration URL with PKCE."""
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri or self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        
        return f"{self.config.registration_endpoint}?{urlencode(params)}"
    
    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens."""
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
            "code_verifier": code_verifier,
        }
        
        # Add client secret if configured (confidential client)
        if self.config.client_secret:
            token_data["client_secret"] = self.config.client_secret
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            response = await client.post(
                self.config.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            
            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.text}")
                raise ValueError(f"Token exchange failed: {response.status_code}")
            
            return response.json()
    
    def parse_id_token(self, id_token: str, access_token: str | None = None) -> OIDCUserInfo:
        """
        Parse user claims from ID token.
        
        The ID token is already validated via PKCE during the code exchange,
        so we only need to decode the claims without signature verification.
        All user claims are included in the ID token per Keycloak configuration.
        """
        try:
            oidc_user = build_oidc_user_info(id_token=id_token, access_token=access_token)
            logger.debug("Parsed Keycloak token claims for subject: %s", oidc_user.sub)
            return oidc_user
        except ValueError as e:
            logger.error(f"Failed to parse ID token: {e}")
            raise ValueError(f"Invalid ID token: {e}")
    
    def get_logout_url(self, id_token: str | None = None, post_logout_redirect_uri: str | None = None) -> str:
        """Get Keycloak logout URL for SSO logout."""
        params = {
            "client_id": self.config.client_id,
        }
        
        if id_token:
            params["id_token_hint"] = id_token
        
        # Redirect to home page after logout
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        
        return f"{self.config.logout_endpoint}?{urlencode(params)}"
