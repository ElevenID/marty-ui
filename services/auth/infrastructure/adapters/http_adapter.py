"""
Auth Service HTTP Adapter (FastAPI)

FastAPI router providing the HTTP API for the Auth service.
This is the inbound adapter that exposes the use cases via REST.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Annotated, Any
from urllib.parse import quote, urlparse

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from ...application.ports import (
    HandleCallbackCommand,
    InitiateLoginCommand,
    LogoutCommand,
    ValidateSessionQuery,
)
from ...application.use_cases import AuthenticateUseCase, SessionUseCase
from ...domain.entities import AuthenticatedUser, Session, UserType

try:
    from .keycloak_admin_adapter import KeycloakAdminAdapter
except ImportError:
    KeycloakAdminAdapter = None  # type: ignore[assignment,misc]

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

# Credential-login dependencies (injected at startup)
_redis_client: Any | None = None  # redis.asyncio.Redis
_session_repository: Any | None = None  # RedisSessionRepository
_flow_service_url: str = os.environ.get("FLOW_SERVICE_URL", "http://flow:8011")
_credential_login_policy_id: str = os.environ.get("CREDENTIAL_LOGIN_POLICY_ID", "")
_auth_service_internal_url: str = os.environ.get(
    "AUTH_SERVICE_INTERNAL_URL", "http://auth:8001"
)
_kc_admin_adapter: Any | None = None  # KeycloakAdminAdapter | None

# Redis key prefixes for credential-login state
_PENDING_KEY = "marty:cred_login:pending:"
_COMPLETE_KEY = "marty:cred_login:complete:"
_PENDING_TTL = 900   # 15 minutes
_COMPLETE_TTL = 300  # 5 minutes (consumed once)


def _sanitize_redirect_uri(redirect_uri: str | None, ui_base_url: str) -> str:
    """
    Sanitize a post-login redirect URI.

    - None / empty  → "/"
    - Relative path (starts with "/") → kept as-is (safe)
    - Absolute URL matching ui_base_url host → kept as-is (same origin)
    - Absolute URL pointing elsewhere (e.g. localhost) → path extracted,
      then prepended with ui_base_url (prevents open redirect)
    """
    if not redirect_uri:
        return "/"
    if redirect_uri.startswith("/"):
        return redirect_uri
    # Absolute URL — only allow same origin as ui_base_url
    try:
        parsed = urlparse(redirect_uri)
        base = urlparse(ui_base_url)
        if parsed.scheme == base.scheme and parsed.netloc == base.netloc:
            return redirect_uri
        # Different host (e.g. localhost) — keep only the path
        logger.warning(
            "redirect_uri host %s does not match UI base %s — stripping to path",
            parsed.netloc,
            base.netloc,
        )
        return parsed.path or "/"
    except Exception:
        return "/"


def configure_auth_router(
    authenticate_use_case: AuthenticateUseCase,
    session_use_case: SessionUseCase,
    cookie_config: dict[str, Any] | None = None,
    ui_base_url: str | None = None,
    redis_client: Any | None = None,
    session_repository: Any | None = None,
    flow_service_url: str | None = None,
    credential_login_policy_id: str | None = None,
    auth_service_internal_url: str | None = None,
    kc_admin_adapter: Any | None = None,
) -> None:
    """Configure the router with use cases and config."""
    global _authenticate_use_case, _session_use_case, _cookie_config, _ui_base_url
    global _redis_client, _session_repository, _flow_service_url
    global _credential_login_policy_id, _auth_service_internal_url, _kc_admin_adapter
    _authenticate_use_case = authenticate_use_case
    _session_use_case = session_use_case
    if cookie_config:
        _cookie_config.update(cookie_config)
    if ui_base_url:
        _ui_base_url = ui_base_url
    if redis_client is not None:
        _redis_client = redis_client
    if session_repository is not None:
        _session_repository = session_repository
    if flow_service_url:
        _flow_service_url = flow_service_url
    if credential_login_policy_id:
        _credential_login_policy_id = credential_login_policy_id
    if auth_service_internal_url:
        _auth_service_internal_url = auth_service_internal_url
    if kc_admin_adapter is not None:
        _kc_admin_adapter = kc_admin_adapter


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
    safe_redirect = _sanitize_redirect_uri(redirect_uri, _ui_base_url)
    result = await use_case.initiate_login(
        InitiateLoginCommand(redirect_uri=safe_redirect)
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
    safe_redirect = _sanitize_redirect_uri(redirect_uri, _ui_base_url)
    result = await use_case.initiate_registration(
        InitiateLoginCommand(redirect_uri=safe_redirect)
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
        
        # Resolve redirect_uri: sanitize (strip any cross-origin URL) then make absolute
        raw_redirect = result.redirect_uri
        redirect_uri = _sanitize_redirect_uri(raw_redirect, _ui_base_url)
        if redirect_uri.startswith("/"):
            redirect_uri = f"{_ui_base_url}{redirect_uri}"
        
        logger.info(
            "Callback redirect: raw=%r sanitized=%r final=%r ui_base=%r",
            raw_redirect, _sanitize_redirect_uri(raw_redirect, _ui_base_url), redirect_uri, _ui_base_url,
        )
        
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
# Credential Login (SD-JWT / OID4VP) Endpoints
# =============================================================================

_CREDENTIAL_LOGIN_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login with Credential &mdash; Marty</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #f5f6fa; display:flex;
           justify-content:center; align-items:center; min-height:100vh; margin:0 }}
    .card {{ background:#fff; border-radius:12px; box-shadow:0 2px 16px rgba(0,0,0,.1);
             padding:2.5rem 2rem; max-width:380px; width:100%; text-align:center }}
    h1 {{ font-size:1.25rem; margin:0 0 .5rem }}
    p  {{ color:#666; font-size:.9rem; margin:0 0 1.5rem }}
    .qr img {{ width:220px; height:220px; border:1px solid #e0e0e0; border-radius:8px }}
    .status {{ margin-top:1.25rem; font-size:.875rem; color:#555 }}
    .spinner {{ display:inline-block; width:14px; height:14px; border:2px solid #ccc;
                border-top-color:#4a90e2; border-radius:50%; animation:spin .8s linear infinite;
                vertical-align:middle; margin-right:6px }}
    @keyframes spin {{ to {{ transform:rotate(360deg) }} }}
    .done {{ color:#27ae60; font-weight:600 }}
    .btn {{ display:inline-block; margin-top:1rem; padding:.55rem 1.25rem; border-radius:8px;
            background:#4a90e2; color:#fff; text-decoration:none; font-size:.875rem }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Login with Credential</h1>
    <p>Scan with your Marty wallet to authenticate</p>
    <div class="qr">
      <img
        src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=5&data={qr_encoded}"
        alt="OID4VP QR code"
      >
    </div>
    <div class="status" id="status">
      <span class="spinner"></span> Waiting for wallet response&hellip;
    </div>
  </div>
  <script>
    (function() {{
      var nonce = {nonce_json};
      var attempts = 0;
      var max = 180; // 3 min at 1 req/s
      var timer = setInterval(function() {{
        attempts++;
        if (attempts > max) {{
          clearInterval(timer);
          document.getElementById('status').innerHTML = '<span style="color:#e74c3c">Timed out. <a href="/v1/auth/credential-login">Try again</a></span>';
          return;
        }}
        fetch('/v1/auth/credential-login/status?nonce=' + encodeURIComponent(nonce))
          .then(function(r) {{ return r.json(); }})
          .then(function(d) {{
            if (d.status === 'completed') {{
              clearInterval(timer);
              document.getElementById('status').innerHTML = '<span class="done">&#10003; Verified! Redirecting&hellip;</span>';
              window.location.href = d.redirect_to || '/';
            }} else if (d.status === 'failed') {{
              clearInterval(timer);
              document.getElementById('status').innerHTML = '<span style="color:#e74c3c">Verification failed. <a href="/v1/auth/credential-login">Try again</a></span>';
            }}
          }})
          .catch(function() {{ /* network hiccup — keep polling */ }});
      }}, 1000);
    }})();
  </script>
</body>
</html>
"""


@router.get("/credential-login", response_class=HTMLResponse)
async def credential_login(request: Request) -> HTMLResponse:
    """
    Initiate an OID4VP login flow.

    Returns an HTML page with a QR code for the Marty wallet to scan.
    Polling via /credential-login/status detects completion.
    """
    if not _credential_login_policy_id:
        raise HTTPException(status_code=503, detail="Credential login not configured (CREDENTIAL_LOGIN_POLICY_ID missing)")
    if _redis_client is None:
        raise HTTPException(status_code=503, detail="Session store not available")

    nonce = secrets.token_urlsafe(32)
    callback_url = (
        f"{_auth_service_internal_url}/internal/v1/auth/credential-verified"
        f"?nonce={nonce}"
    )

    # Start OID4VP flow
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{_flow_service_url}/v1/flows/verify",
                json={
                    "presentation_policy_id": _credential_login_policy_id,
                    "callback_url": callback_url,
                },
                headers={"X-User-Id": "auth-service"},
            )
            resp.raise_for_status()
            flow_data = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error(f"Flow service returned {exc.response.status_code}: {exc.response.text}")
        raise HTTPException(status_code=502, detail="Could not initiate credential flow")
    except httpx.RequestError as exc:
        logger.error(f"Flow service unreachable: {exc}")
        raise HTTPException(status_code=503, detail="Flow service unavailable")

    instance_id: str = flow_data.get("instance_id", "")
    # request_uri is the full openid4vp://authorize?... URI
    oid4vp_uri: str = flow_data.get("request_uri", flow_data.get("qr_code_data", ""))

    # Persist pending state
    await _redis_client.setex(
        f"{_PENDING_KEY}{nonce}",
        _PENDING_TTL,
        json.dumps({"nonce": nonce, "flow_instance_id": instance_id, "status": "pending"}),
    )

    qr_encoded = quote(oid4vp_uri, safe="")
    html = _CREDENTIAL_LOGIN_PAGE.format(
        qr_encoded=qr_encoded,
        nonce_json=json.dumps(nonce),
    )
    return HTMLResponse(content=html)


@router.get("/credential-login/status")
async def credential_login_status(nonce: str) -> dict[str, Any]:
    """
    Poll credential-login completion status.

    Returns ``{"status": "pending"}`` while waiting, or
    ``{"status": "completed", "redirect_to": "/v1/auth/credential-login/finalize?nonce=..."}``
    when the wallet has verified successfully.
    """
    if _redis_client is None:
        raise HTTPException(status_code=503, detail="Session store not available")

    raw = await _redis_client.get(f"{_COMPLETE_KEY}{nonce}")
    if raw:
        data = json.loads(raw)
        status = data.get("status", "completed")
        if status == "completed":
            return {
                "status": "completed",
                "redirect_to": f"/v1/auth/credential-login/finalize?nonce={quote(nonce, safe='')}",
            }
        return {"status": status, "redirect_to": data.get("redirect_to", "/")}

    # Check if the nonce even exists (i.e. not expired)
    pending = await _redis_client.get(f"{_PENDING_KEY}{nonce}")
    if not pending:
        return {"status": "expired"}

    return {"status": "pending"}


@router.get("/credential-login/finalize")
async def credential_login_finalize(
    nonce: str,
    response: Response,
) -> RedirectResponse:
    """
    Finalise credential login by setting the session cookie.

    The polling JS navigates here once the wallet has verified.
    Reads the completed session from Redis, sets the sessionId cookie,
    and redirects to the home page.
    """
    if _redis_client is None:
        raise HTTPException(status_code=503, detail="Session store not available")

    raw = await _redis_client.get(f"{_COMPLETE_KEY}{nonce}")
    if not raw:
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error=Login+session+expired", status_code=302
        )

    data = json.loads(raw)
    if data.get("status") != "completed":
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error=Verification+failed", status_code=302
        )

    session_id: str = data.get("session_id", "")
    if not session_id:
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error=Session+creation+failed", status_code=302
        )

    # Consume the completion key so it can't be replayed
    await _redis_client.delete(f"{_COMPLETE_KEY}{nonce}")

    redirect = RedirectResponse(url=f"{_ui_base_url}/", status_code=302)
    redirect.set_cookie(
        key=_cookie_config["key"],
        value=session_id,
        httponly=_cookie_config["httponly"],
        secure=_cookie_config["secure"],
        samesite=_cookie_config["samesite"],
        max_age=_cookie_config["max_age"],
        path=_cookie_config["path"],
    )
    logger.info(f"Credential login finalised: session={session_id[:8]}...")
    return redirect


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


class CredentialVerifiedPayload(BaseModel):
    """Callback payload from the flow service after OID4VP verification."""

    flow_instance_id: str
    result: str              # "passed" | "failed" | "partial"
    decision: str            # "allow" | "deny" | "manual_review"
    decision_reason: str = ""
    verified_claims: dict[str, Any] = {}
    presentation_policy_id: str = ""
    completed_at: str = ""


@internal_router.post("/credential-verified")
async def credential_verified(
    payload: CredentialVerifiedPayload,
    nonce: str,
    request: Request,
) -> dict[str, Any]:
    """
    Receive verification result callback from the flow service.

    Called by the flow service after a wallet submits a VP token.
    Creates a session for the verified user and signals the polling
    endpoint that login is complete.

    This endpoint is NOT exposed via the gateway.
    """
    if _redis_client is None or _session_repository is None:
        raise HTTPException(status_code=503, detail="Session store not available")

    # Locate the pending login state
    pending_raw = await _redis_client.get(f"{_PENDING_KEY}{nonce}")
    if not pending_raw:
        logger.warning(f"credential-verified: nonce {nonce[:8]}... not found or expired")
        raise HTTPException(status_code=404, detail="Login session expired or not found")

    if payload.decision != "allow" or payload.result == "failed":
        logger.info(f"Credential verification denied: {payload.decision} / {payload.result}")
        await _redis_client.setex(
            f"{_COMPLETE_KEY}{nonce}",
            _COMPLETE_TTL,
            json.dumps({"status": "failed", "reason": payload.decision_reason}),
        )
        await _redis_client.delete(f"{_PENDING_KEY}{nonce}")
        return {"ok": True, "status": "denied"}

    # Extract identity claims from the VP
    claims = payload.verified_claims
    email: str = claims.get("email", "")
    given_name: str | None = claims.get("given_name")
    family_name: str | None = claims.get("family_name")
    organization_id: str | None = claims.get("organization_id")
    role: str = claims.get("role", "applicant")
    member_id: str | None = claims.get("member_id")

    if not email:
        logger.error("credential-verified: no email in verified_claims")
        raise HTTPException(status_code=422, detail="Credential missing email claim")

    # Derive a stable user_id: prefer sub claim, then fall back to a deterministic UUID
    user_id: str = claims.get("sub") or claims.get("subject") or ""
    if not user_id:
        import hashlib as _hashlib
        user_id = str(
            __import__("uuid").UUID(
                bytes=_hashlib.sha256(email.lower().encode()).digest()[:16]
            )
        )

    # Map credential role to UserType
    role_map = {"administrator": UserType.ADMINISTRATOR, "vendor": UserType.VENDOR}
    user_type: UserType = role_map.get(role, UserType.APPLICANT)

    user = AuthenticatedUser(
        user_id=user_id,
        email=email,
        given_name=given_name,
        family_name=family_name,
        user_type=user_type,
        roles=[role],
        organization_id=organization_id,
        applicant_id=member_id,
    )

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    session = Session.create(
        user=user,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Optionally enrich with KC-issued tokens via token exchange
    if _kc_admin_adapter is not None:
        try:
            kc_user_id = await _kc_admin_adapter.get_or_create_user(
                email=email,
                given_name=given_name,
                family_name=family_name,
                role=role,
            )
            if kc_user_id:
                kc_tokens = await _kc_admin_adapter.exchange_token_for_user(kc_user_id)
                if kc_tokens:
                    session.id_token = kc_tokens.get("id_token")
                    session.refresh_token = kc_tokens.get("refresh_token")
                    logger.debug(f"KC tokens obtained for {email}")
        except Exception as kc_exc:
            logger.warning(f"KC token exchange optional step failed: {kc_exc}")

    await _session_repository.save(session)

    logger.info(
        f"Credential login succeeded: user={email} session={session.session_id[:8]}..."
    )

    # Signal the polling endpoint
    await _redis_client.setex(
        f"{_COMPLETE_KEY}{nonce}",
        _COMPLETE_TTL,
        json.dumps({
            "status": "completed",
            "session_id": session.session_id,
        }),
    )
    # Clean up pending key
    await _redis_client.delete(f"{_PENDING_KEY}{nonce}")

    return {"ok": True, "status": "completed", "session_id": session.session_id}
