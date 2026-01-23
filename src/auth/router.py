"""
Authentication API Router

FastAPI router providing OIDC authentication endpoints:
- GET /auth/login - Redirect to Keycloak with PKCE
- GET /auth/callback - Handle OIDC callback, create session
- POST /auth/logout - Full SSO logout (local + Keycloak)
- GET /auth/me - Get current user info
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from .cache import AuthCacheService, AuthCacheConfig, create_auth_cache_service
from .config import AuthConfig, CookieConfig, OIDCConfig
from .provisioning import JITProvisioningService, OIDCUserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


# =============================================================================
# Response Models
# =============================================================================


class UserInfoResponse(BaseModel):
    """User information response."""

    user_id: str
    email: str
    username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    user_type: str
    applicant_id: str | None = None
    roles: list[str] = []
    organization_id: str | None = None
    organization_name: str | None = None
    organization: dict[str, Any] | None = None
    onboarding_completed: str | None = None


class AuthStatusResponse(BaseModel):
    """Authentication status response."""

    authenticated: bool
    user: UserInfoResponse | None = None


# =============================================================================
# Dependencies
# =============================================================================


def get_auth_config() -> AuthConfig:
    """Get authentication configuration."""
    return AuthConfig.from_env()


async def get_redis_client():
    """Get Redis client for session storage."""
    import redis.asyncio as redis

    config = AuthConfig.from_env()
    return redis.from_url(config.redis.url, decode_responses=True)


async def get_session_manager():
    """Get session manager instance."""
    from mmf.adapters.session import RedisSessionAdapter

    redis_client = await get_redis_client()
    config = AuthConfig.from_env()
    return RedisSessionAdapter(
        redis_client=redis_client,
        default_timeout_minutes=config.cookie.max_age // 60,
        max_sessions_per_user=config.redis.max_sessions_per_user,
        key_prefix=config.redis.key_prefix,
    )


# Auth cache service singleton
_auth_cache_service: AuthCacheService | None = None


async def get_auth_cache_service() -> AuthCacheService:
    """
    Get auth cache service instance.
    
    Uses MMF's cache infrastructure for PKCE state storage,
    providing consistent metrics and namespace isolation.
    """
    global _auth_cache_service
    if _auth_cache_service is None:
        _auth_cache_service = await create_auth_cache_service()
    return _auth_cache_service


async def get_provisioning_service():
    """Get JIT provisioning service."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    import os

    db_url = os.environ.get(
        "APPLICANT_DB_URL",
        "postgresql+asyncpg://marty:marty@localhost:5432/marty_applicants",
    )
    engine = create_async_engine(db_url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    from .provisioning import ApplicantRepositoryAdapter

    repo = ApplicantRepositoryAdapter(session_factory)
    return JITProvisioningService(applicant_repository=repo)


# =============================================================================
# PKCE Utilities
# =============================================================================


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge."""
    # Generate code verifier (43-128 chars)
    code_verifier = secrets.token_urlsafe(64)

    # Generate code challenge (S256)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    return code_verifier, code_challenge


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/login")
async def login(
    request: Request,
    redirect_uri: str | None = None,
    config: AuthConfig = Depends(get_auth_config),
) -> RedirectResponse:
    """
    Initiate OIDC login flow.

    Redirects to Keycloak authorization endpoint with PKCE.
    Stores PKCE verifier and original redirect_uri in session state.
    """
    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Store state data using MMF cache infrastructure
    auth_cache = await get_auth_cache_service()
    await auth_cache.store_pkce_state(
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri or "/",
    )

    # Build authorization URL
    params = {
        "response_type": "code",
        "client_id": config.oidc.client_id,
        "redirect_uri": config.oidc.redirect_uri,
        "scope": " ".join(config.oidc.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    auth_url = f"{config.oidc.authorization_endpoint}?{urlencode(params)}"
    logger.info(f"Redirecting to OIDC provider for login")

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/register")
async def register(
    request: Request,
    redirect_uri: str | None = None,
    config: AuthConfig = Depends(get_auth_config),
) -> RedirectResponse:
    """
    Initiate OIDC registration flow.

    Redirects to Keycloak registration page with PKCE.
    Uses the /registrations endpoint to go directly to the registration form.
    """
    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Store state data using MMF cache infrastructure
    auth_cache = await get_auth_cache_service()
    await auth_cache.store_pkce_state(
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri or "/",
    )

    # Build registration URL - use /registrations endpoint instead of /auth
    # This takes the user directly to the registration form
    params = {
        "response_type": "code",
        "client_id": config.oidc.client_id,
        "redirect_uri": config.oidc.redirect_uri,
        "scope": " ".join(config.oidc.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    # Replace /auth with /registrations in the authorization endpoint
    registration_endpoint = config.oidc.authorization_endpoint.replace(
        "/protocol/openid-connect/auth",
        "/protocol/openid-connect/registrations"
    )
    registration_url = f"{registration_endpoint}?{urlencode(params)}"
    logger.info(f"Redirecting to OIDC provider for registration")

    return RedirectResponse(url=registration_url, status_code=302)


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    config: AuthConfig = Depends(get_auth_config),
) -> RedirectResponse:
    """
    Handle OIDC callback after successful authentication.

    Exchanges authorization code for tokens, provisions user,
    creates session, and sets secure cookie.
    
    Also handles error responses from Keycloak gracefully.
    """
    # Handle OAuth errors from Keycloak (e.g., user cancelled)
    if error:
        logger.warning(f"OIDC error callback: {error} - {error_description}")
        # Redirect to home with error message
        error_msg = error_description or error
        return RedirectResponse(
            url=f"/?auth_error={error_msg}",
            status_code=302
        )
    
    # Validate required parameters
    if not code or not state:
        logger.warning("Callback missing code or state parameter")
        return RedirectResponse(
            url="/?auth_error=Missing+authentication+parameters.+Please+try+again.",
            status_code=302
        )
    
    # Consume PKCE state using MMF cache infrastructure (single-use pattern)
    auth_cache = await get_auth_cache_service()
    pkce_state = await auth_cache.consume_pkce_state(state)
    
    if not pkce_state:
        logger.warning(f"Invalid or expired state: {state[:20]}...")
        # Redirect to home with friendly error instead of showing JSON error
        return RedirectResponse(
            url="/?auth_error=Your+session+has+expired.+Please+try+logging+in+again.",
            status_code=302
        )

    code_verifier = pkce_state.code_verifier
    original_redirect = pkce_state.redirect_uri

    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.oidc.redirect_uri,
            "client_id": config.oidc.client_id,
            "code_verifier": code_verifier,
        }

        # Add client secret if configured (confidential client)
        if config.oidc.client_secret:
            token_data["client_secret"] = config.oidc.client_secret

        try:
            response = await client.post(
                config.oidc.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"Token exchange failed: {e.response.text}")
            raise HTTPException(status_code=401, detail="Authentication failed")

        tokens = response.json()

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    id_token = tokens.get("id_token")
    expires_in = tokens.get("expires_in", 300)

    # Get user info from token or userinfo endpoint
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                config.oidc.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            user_claims = response.json()
        except httpx.HTTPStatusError:
            # Fall back to decoding ID token (not verified, just for claims)
            import json
            import base64

            parts = id_token.split(".")
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            user_claims = json.loads(base64.urlsafe_b64decode(payload))

    # Create OIDC user info
    oidc_user = OIDCUserInfo.from_claims(user_claims)

    # JIT provisioning
    provisioning = await get_provisioning_service()
    provision_result = await provisioning.provision_user(oidc_user)

    # Create session
    session_manager = await get_session_manager()
    session = await session_manager.create_session(
        user_id=oidc_user.sub,
        timeout_minutes=config.cookie.max_age // 60,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        # Store user info in session
        email=oidc_user.email,
        username=oidc_user.preferred_username or oidc_user.email,
        given_name=oidc_user.given_name,
        family_name=oidc_user.family_name,
        user_type=provision_result.user_type,
        applicant_id=provision_result.applicant_id,
        roles=oidc_user.roles or [],
        organization_id=provision_result.organization_id or oidc_user.organization_id,
        organization_name=provision_result.organization_name or oidc_user.organization_name,
        organization=oidc_user.organization,
        onboarding_completed=user_claims.get("onboarding_completed")
        or user_claims.get("attributes", {}).get("onboarding_completed", [None])[0],
        access_token_expires_at=(
            datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        ).isoformat(),
    )

    # Store tokens in session
    await session_manager.store_refresh_token(
        session.session_id,
        refresh_token,
        expires_in_seconds=7 * 24 * 60 * 60,  # 7 days
    )
    if id_token:
        await session_manager.store_id_token(session.session_id, id_token)

    # Determine redirect destination based on user role + onboarding state
    final_redirect = original_redirect
    user_attrs = user_claims.get("attributes", {})
    onboarding_completed = user_claims.get("onboarding_completed") or user_attrs.get(
        "onboarding_completed"
    )
    org_id = (
        user_claims.get("organization_id")
        or user_attrs.get("organization_id")
        or oidc_user.organization_id
    )

    if provision_result.is_new_applicant:
        final_redirect = "/onboarding"
        logger.info(f"New user {oidc_user.email} redirected to onboarding")
    elif provision_result.user_type == "administrator":
        final_redirect = original_redirect or "/dashboard"
    elif provision_result.user_type == "vendor":
        if not onboarding_completed or not org_id:
            final_redirect = "/onboarding"
            logger.info(f"Vendor {oidc_user.email} needs onboarding")
        else:
            final_redirect = original_redirect or "/vendor"
    else:
        if not onboarding_completed:
            final_redirect = "/onboarding"
            logger.info(f"Returning user {oidc_user.email} needs onboarding")
        else:
            final_redirect = original_redirect or "/credentials"

    # Create response with session cookie
    response = RedirectResponse(url=final_redirect, status_code=302)
    response.set_cookie(
        key=config.cookie.name,
        value=session.session_id,
        max_age=config.cookie.max_age,
        path=config.cookie.path,
        domain=config.cookie.domain,
        secure=config.cookie.secure,
        httponly=config.cookie.httponly,
        samesite=config.cookie.samesite,
    )

    logger.info(f"User {oidc_user.email} logged in successfully")
    return response


@router.post("/logout")
async def logout(
    request: Request,
    config: AuthConfig = Depends(get_auth_config),
) -> RedirectResponse:
    """
    Full SSO logout.

    Terminates local session and redirects to Keycloak end_session_endpoint
    with id_token_hint for full SSO logout.
    """
    # Get session ID from cookie
    session_id = request.cookies.get(config.cookie.name)
    logger.info(f"Logout requested. Cookie name: {config.cookie.name}, Session ID: {session_id}")
    logger.info(f"Cookie config - domain: {config.cookie.domain}, path: {config.cookie.path}")

    id_token = None
    if session_id:
        session_manager = await get_session_manager()

        # Get ID token for SSO logout
        id_token = await session_manager.get_id_token(session_id)

        # Terminate local session
        from mmf.core.security.domain.models.session import SessionEventType

        await session_manager.terminate_session(session_id, SessionEventType.LOGOUT)

    # Build Keycloak logout URL
    logout_params = {
        "post_logout_redirect_uri": config.oidc.post_logout_redirect_uri,
        "client_id": config.oidc.client_id,
    }
    if id_token:
        logout_params["id_token_hint"] = id_token

    logout_url = f"{config.oidc.end_session_endpoint}?{urlencode(logout_params)}"

    # Create response that clears cookie and redirects to Keycloak logout
    response = RedirectResponse(url=logout_url, status_code=302)
    response.delete_cookie(
        key=config.cookie.name,
        path=config.cookie.path,
        domain=config.cookie.domain,
    )

    logger.info("User logged out")
    return response


@router.get("/me", response_model=AuthStatusResponse)
async def get_current_user(
    request: Request,
    config: AuthConfig = Depends(get_auth_config),
) -> AuthStatusResponse:
    """
    Get current authenticated user information.

    Returns user info from session or unauthenticated status.
    """
    session_id = request.cookies.get(config.cookie.name)

    if not session_id:
        return AuthStatusResponse(authenticated=False)

    session_manager = await get_session_manager()
    session = await session_manager.get_session(session_id)

    if not session:
        return AuthStatusResponse(authenticated=False)

    # Check if access token needs refresh
    if await session_manager.should_refresh_token(session_id):
        await _refresh_access_token(session_id, session_manager, config)

    # Build user info from session attributes
    attrs = session.attributes
    user = UserInfoResponse(
        user_id=session.user_id,
        email=attrs.get("email", ""),
        username=attrs.get("username"),
        given_name=attrs.get("given_name"),
        family_name=attrs.get("family_name"),
        user_type=attrs.get("user_type", "applicant"),
        applicant_id=attrs.get("applicant_id"),
        roles=attrs.get("roles", []),
        organization_id=attrs.get("organization_id"),
        organization_name=attrs.get("organization_name"),
        organization=attrs.get("organization"),
        onboarding_completed=attrs.get("onboarding_completed"),
    )

    return AuthStatusResponse(authenticated=True, user=user)


async def _refresh_access_token(
    session_id: str,
    session_manager,
    config: AuthConfig,
) -> bool:
    """Refresh access token using refresh token (sliding window)."""
    refresh_token = await session_manager.get_refresh_token(session_id)
    if not refresh_token:
        return False

    async with httpx.AsyncClient() as client:
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.oidc.client_id,
        }
        if config.oidc.client_secret:
            token_data["client_secret"] = config.oidc.client_secret

        try:
            response = await client.post(
                config.oidc.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.warning(f"Token refresh failed: {e}")
            return False

        tokens = response.json()

    # Update tokens in session
    access_token = tokens["access_token"]
    expires_in = tokens.get("expires_in", 300)
    new_refresh_token = tokens.get("refresh_token", refresh_token)

    await session_manager.update_access_token(session_id, access_token, expires_in)

    if new_refresh_token != refresh_token:
        await session_manager.store_refresh_token(
            session_id,
            new_refresh_token,
            expires_in_seconds=7 * 24 * 60 * 60,
        )

    logger.debug(f"Refreshed access token for session {session_id}")
    return True


# =============================================================================
# Role-Based Access Dependencies
# =============================================================================


async def require_authenticated(
    request: Request,
    config: AuthConfig = Depends(get_auth_config),
) -> AuthStatusResponse:
    """Require authenticated user, returns user info or raises 401."""
    auth_status = await get_current_user(request, config)
    if not auth_status.authenticated or not auth_status.user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )
    return auth_status


async def require_org_admin(
    request: Request,
    config: AuthConfig = Depends(get_auth_config),
) -> AuthStatusResponse:
    """Require organization admin, returns user info or raises 403.
    
    Checks that the user is authenticated and has admin/owner role
    in their organization, or is a platform admin.
    """
    auth_status = await require_authenticated(request, config)
    user = auth_status.user
    
    # Platform admins have full access (check multiple role names used across Keycloak configs)
    roles = user.roles or []
    if "platform_admin" in roles or "admin" in roles or "administrator" in roles:
        return auth_status
    
    # Check for org admin/owner role
    if "org_admin" in roles or "org_owner" in roles or "owner" in roles or "vendor" in roles:
        return auth_status
    
    # Check if user has an organization and is admin there
    if user.organization_id and ("admin" in roles or "owner" in roles or "vendor" in roles):
        return auth_status
    
    raise HTTPException(
        status_code=403,
        detail="Organization admin access required",
    )
