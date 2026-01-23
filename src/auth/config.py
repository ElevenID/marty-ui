"""
Authentication Configuration

Environment-aware configuration for authentication cookies and OIDC settings.
Follows industry standards: OWASP cookie security recommendations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class CookieConfig:
    """
    Cookie configuration with environment-specific security settings.

    Development: Secure=False, SameSite=Lax (works with localhost)
    Production: Secure=True, SameSite=Strict, __Host- prefix (OWASP best practice)
    """

    name: str = "marty_session"
    max_age: int = 1800  # 30 minutes
    path: str = "/"
    domain: str | None = None
    secure: bool = False
    httponly: bool = True
    samesite: Literal["lax", "strict", "none"] = "lax"

    @classmethod
    def from_env(cls) -> CookieConfig:
        """Create configuration from environment variables."""
        is_production = os.environ.get("ENVIRONMENT", "development").lower() == "production"
        
        if is_production:
            # Production: strict security settings per OWASP
            return cls(
                name="__Host-marty_session",  # __Host- prefix for strict security
                max_age=int(os.environ.get("SESSION_MAX_AGE", "1800")),
                path="/",
                domain=None,  # __Host- cookies must not have domain
                secure=True,
                httponly=True,
                samesite="strict",
            )
        else:
            # Development: relaxed for localhost
            return cls(
                name="marty_session",
                max_age=int(os.environ.get("SESSION_MAX_AGE", "1800")),
                path="/",
                domain=os.environ.get("COOKIE_DOMAIN"),
                secure=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
                httponly=True,
                samesite=os.environ.get("COOKIE_SAMESITE", "lax").lower(),  # type: ignore
            )


@dataclass
class OIDCConfig:
    """OIDC provider configuration."""

    issuer_url: str = ""
    backend_issuer_url: str = ""  # For backend-to-backend communication (docker internal)
    client_id: str = ""
    client_secret: str | None = None  # None for public clients
    redirect_uri: str = ""
    post_logout_redirect_uri: str = ""
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email", "roles"])
    
    # Token settings
    access_token_refresh_threshold_seconds: int = 300  # 5 minutes

    @classmethod
    def from_env(cls) -> OIDCConfig:
        """Create configuration from environment variables."""
        return cls(
            issuer_url=os.environ.get(
                "OIDC_ISSUER_URL",
                "http://localhost:8180/realms/marty",
            ),
            backend_issuer_url=os.environ.get(
                "OIDC_BACKEND_ISSUER_URL",
                "http://keycloak:8080/realms/marty",  # Internal docker network
            ),
            client_id=os.environ.get("OIDC_CLIENT_ID", "marty-ui"),
            client_secret=os.environ.get("OIDC_CLIENT_SECRET"),  # None for public clients
            redirect_uri=os.environ.get(
                "OIDC_REDIRECT_URI",
                "http://localhost:9080/auth/callback",
            ),
            post_logout_redirect_uri=os.environ.get(
                "OIDC_POST_LOGOUT_REDIRECT_URI",
                "http://localhost:9080",
            ),
            scopes=os.environ.get(
                "OIDC_SCOPES",
                "openid profile email roles marty-user-attributes",
            ).split(),
            access_token_refresh_threshold_seconds=int(
                os.environ.get("OIDC_REFRESH_THRESHOLD_SECONDS", "300")
            ),
        )

    @property
    def well_known_url(self) -> str:
        """Get OIDC well-known configuration URL (frontend-facing)."""
        return f"{self.issuer_url.rstrip('/')}/.well-known/openid-configuration"

    @property
    def backend_well_known_url(self) -> str:
        """Get OIDC well-known configuration URL (backend-internal)."""
        return f"{self.backend_issuer_url.rstrip('/')}/.well-known/openid-configuration"

    @property
    def authorization_endpoint(self) -> str:
        """Get authorization endpoint (frontend-facing for browser redirect)."""
        return f"{self.issuer_url.rstrip('/')}/protocol/openid-connect/auth"

    @property
    def token_endpoint(self) -> str:
        """Get token endpoint (backend-internal for server-to-server)."""
        return f"{self.backend_issuer_url.rstrip('/')}/protocol/openid-connect/token"

    @property
    def userinfo_endpoint(self) -> str:
        """Get userinfo endpoint (backend-internal for server-to-server)."""
        return f"{self.backend_issuer_url.rstrip('/')}/protocol/openid-connect/userinfo"

    @property
    def end_session_endpoint(self) -> str:
        """Get end session (logout) endpoint (frontend-facing for browser redirect)."""
        return f"{self.issuer_url.rstrip('/')}/protocol/openid-connect/logout"


@dataclass
class RedisConfig:
    """Redis configuration for session storage."""

    url: str = "redis://localhost:6379/0"
    key_prefix: str = "marty:"
    session_ttl_seconds: int = 1800  # 30 minutes
    max_sessions_per_user: int = 5

    @classmethod
    def from_env(cls) -> RedisConfig:
        """Create configuration from environment variables."""
        return cls(
            url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            key_prefix=os.environ.get("REDIS_KEY_PREFIX", "marty:"),
            session_ttl_seconds=int(os.environ.get("SESSION_TTL_SECONDS", "1800")),
            max_sessions_per_user=int(os.environ.get("MAX_SESSIONS_PER_USER", "5")),
        )


@dataclass
class AuthConfig:
    """Combined authentication configuration."""

    cookie: CookieConfig
    oidc: OIDCConfig
    redis: RedisConfig
    session_secret: str = ""

    @classmethod
    def from_env(cls) -> AuthConfig:
        """Create full auth configuration from environment."""
        return cls(
            cookie=CookieConfig.from_env(),
            oidc=OIDCConfig.from_env(),
            redis=RedisConfig.from_env(),
            session_secret=os.environ.get(
                "SESSION_SECRET",
                "dev-session-secret-change-in-production",
            ),
        )
