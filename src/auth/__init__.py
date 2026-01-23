"""
Authentication Module

Provides OIDC-based authentication for Marty Trust Services.
"""

from .config import AuthConfig, CookieConfig, OIDCConfig, RedisConfig
from .provisioning import (
    JITProvisioningService,
    OIDCUserInfo,
    ProvisioningResult,
    ApplicantRepositoryAdapter,
)
from .router import router as auth_router

__all__ = [
    "AuthConfig",
    "CookieConfig",
    "OIDCConfig",
    "RedisConfig",
    "JITProvisioningService",
    "OIDCUserInfo",
    "ProvisioningResult",
    "ApplicantRepositoryAdapter",
    "auth_router",
]
