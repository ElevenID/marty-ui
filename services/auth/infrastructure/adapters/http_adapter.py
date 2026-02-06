"""
Auth Service HTTP Adapter (FastAPI)

FastAPI router providing the HTTP API for the Auth service.
This is the inbound adapter that exposes the use cases via REST.
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from ...application.ports import (
    HandleCallbackCommand,
    InitiateLoginCommand,
    LogoutCommand,
    ValidateSessionQuery,
)
from ...application.use_cases import AuthenticateUseCase, SessionUseCase
from ...domain.entities import AuthenticatedUser

logger = logging.getLogger(__name__)

# Create router with versioned prefix
router = APIRouter(prefix="/v1/auth", tags=["authentication"])


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
    onboarding_completed: str | None = None


class AuthStatusResponse(BaseModel):
    """Authentication status response."""
    
    authenticated: bool
    user: UserInfoResponse | None = None


class ApiResponseMeta(BaseModel):
    """API response metadata."""
    
    request_id: str
    timestamp: str


class AuthStatusApiResponse(BaseModel):
    """Wrapped auth status response."""
    
    data: AuthStatusResponse
    meta: ApiResponseMeta


# =============================================================================
# Dependencies
# =============================================================================

# These will be injected by the service container
_authenticate_use_case: AuthenticateUseCase | None = None
_session_use_case: SessionUseCase | None = None
_cookie_config: dict[str, Any] = {
    "key": "sessionId",
    "httponly": True,
    "secure": False,  # Set to True in production
    "samesite": "lax",
    "max_age": 86400,
    "path": "/",
}
_ui_base_url: str = "http://localhost:3000"


def configure_auth_router(
    authenticate_use_case: AuthenticateUseCase,
    session_use_case: SessionUseCase,
    cookie_config: dict[str, Any] | None = None,
    ui_base_url: str | None = None,
) -> None:
    """Configure the router with use cases and config."""
    global _authenticate_use_case, _session_use_case, _cookie_config, _ui_base_url
    _authenticate_use_case = authenticate_use_case
    _session_use_case = session_use_case
    if cookie_config:
        _cookie_config.update(cookie_config)
    if ui_base_url:
        _ui_base_url = ui_base_url


def get_authenticate_use_case() -> AuthenticateUseCase:
    """Get authenticate use case dependency."""
    if _authenticate_use_case is None:
        raise RuntimeError("Auth router not configured")
    return _authenticate_use_case


def get_session_use_case() -> SessionUseCase:
    """Get session use case dependency."""
    if _session_use_case is None:
        raise RuntimeError("Auth router not configured")
    return _session_use_case


async def get_current_session(
    session_id: Annotated[str | None, Cookie(alias="sessionId")] = None,
    session_use_case: SessionUseCase = Depends(get_session_use_case),
) -> AuthenticatedUser | None:
    """Get current authenticated user from session cookie."""
    if not session_id:
        return None
    
    return await session_use_case.get_user(session_id)


async def require_authenticated(
    user: AuthenticatedUser | None = Depends(get_current_session),
) -> AuthenticatedUser:
    """Require authenticated user."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/login")
async def login(
    request: Request,
    redirect_uri: str | None = None,
    use_case: AuthenticateUseCase = Depends(get_authenticate_use_case),
) -> RedirectResponse:
    """
    Initiate OIDC login flow.
    
    Redirects to Keycloak authorization endpoint with PKCE.
    """
    result = await use_case.initiate_login(
        InitiateLoginCommand(redirect_uri=redirect_uri)
    )
    
    logger.info("Redirecting to OIDC provider for login")
    return RedirectResponse(url=result.authorization_url, status_code=302)


@router.get("/register")
async def register(
    request: Request,
    redirect_uri: str | None = None,
    use_case: AuthenticateUseCase = Depends(get_authenticate_use_case),
) -> RedirectResponse:
    """
    Initiate OIDC registration flow.
    
    Redirects to Keycloak registration page with PKCE.
    """
    result = await use_case.initiate_registration(
        InitiateLoginCommand(redirect_uri=redirect_uri)
    )
    
    logger.info("Redirecting to OIDC provider for registration")
    return RedirectResponse(url=result.authorization_url, status_code=302)


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    use_case: AuthenticateUseCase = Depends(get_authenticate_use_case),
) -> RedirectResponse:
    """
    Handle OIDC callback after authentication.
    
    Exchanges authorization code for tokens, creates session,
    and sets secure cookie.
    """
    # Handle OAuth errors from Keycloak
    if error:
        logger.warning(f"OIDC error callback: {error} - {error_description}")
        
        # If user is already authenticated as different user, suggest logout
        if error in ("different_user_authenticated", "already_logged_in"):
            return RedirectResponse(
                url=f"{_ui_base_url}/?auth_error=already_authenticated&message=Please+logout+first+to+login+as+a+different+user",
                status_code=302,
            )
        
        error_msg = error_description or error
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error={error_msg}",
            status_code=302,
        )
    
    # Validate required parameters
    if not code or not state:
        logger.warning("Callback missing code or state parameter")
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error=Missing+authentication+parameters",
            status_code=302,
        )
    
    try:
        # Get client info
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        # Handle callback
        result = await use_case.handle_callback(
            HandleCallbackCommand(
                code=code,
                state=state,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        
        # Make redirect_uri absolute if it's relative
        redirect_uri = result.redirect_uri
        if redirect_uri.startswith("/"):
            redirect_uri = f"{_ui_base_url}{redirect_uri}"
        
        # Create redirect response with session cookie
        response = RedirectResponse(url=redirect_uri, status_code=302)
        
        response.set_cookie(
            key=_cookie_config["key"],
            value=result.session.session_id,
            httponly=_cookie_config["httponly"],
            secure=_cookie_config["secure"],
            samesite=_cookie_config["samesite"],
            max_age=_cookie_config["max_age"],
            path=_cookie_config["path"],
        )
        
        logger.info(f"User {result.session.user.email} authenticated successfully")
        return response
        
    except ValueError as e:
        logger.warning(f"Authentication failed: {e}")
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error=Session+expired.+Please+try+again.",
            status_code=302,
        )


@router.post("/logout")
async def logout(
    session_id: Annotated[str | None, Cookie(alias="sessionId")] = None,
    use_case: AuthenticateUseCase = Depends(get_authenticate_use_case),
) -> RedirectResponse:
    """
    Logout user and revoke session.
    
    Redirects to Keycloak SSO logout to clear all sessions.
    """
    logout_url = "/"  # Default redirect after logout
    
    if session_id:
        result = await use_case.logout(LogoutCommand(session_id=session_id))
        if result and result.sso_logout_url:
            logout_url = result.sso_logout_url
    
    # Create response with cleared cookie
    response = RedirectResponse(url=logout_url, status_code=302)
    response.delete_cookie(
        key=_cookie_config["key"],
        path=_cookie_config["path"],
    )
    
    return response


@router.get("/me", response_model=AuthStatusResponse)
async def get_current_user(
    user: AuthenticatedUser | None = Depends(get_current_session),
) -> AuthStatusResponse:
    """
    Get current authenticated user.
    
    Returns authentication status and user info if authenticated.
    """
    if not user:
        return AuthStatusResponse(authenticated=False, user=None)
    
    return AuthStatusResponse(
        authenticated=True,
        user=UserInfoResponse(
            user_id=user.user_id,
            email=user.email,
            username=user.username,
            given_name=user.given_name,
            family_name=user.family_name,
            user_type=user.user_type.value,
            applicant_id=user.applicant_id,
            roles=user.roles,
            organization_id=user.organization_id,
            organization_name=user.organization_name,
            onboarding_completed=user.onboarding_completed.isoformat() if user.onboarding_completed else None,
        ),
    )


# =============================================================================
# Internal Endpoints (Service-to-Service)
# =============================================================================

internal_router = APIRouter(prefix="/internal/v1/auth", tags=["auth-internal"])


@internal_router.post("/validate-session")
async def validate_session(
    session_id: str,
    session_use_case: SessionUseCase = Depends(get_session_use_case),
) -> dict[str, Any]:
    """
    Validate a session (internal endpoint for service-to-service calls).
    
    This endpoint is NOT exposed via the gateway - only accessible
    internally by other services.
    """
    session = await session_use_case.validate_session(
        ValidateSessionQuery(session_id=session_id)
    )
    
    if not session:
        return {"valid": False, "user": None}
    
    return {
        "valid": True,
        "user": session.user.to_dict(),
        "expires_at": session.expires_at.isoformat(),
    }
