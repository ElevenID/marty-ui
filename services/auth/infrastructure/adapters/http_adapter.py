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

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from ...application.ports import (
    HandleCallbackCommand,
    InitiateLoginCommand,
    LogoutCommand,
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
    picture: str | None = None


class AuthStatusResponse(BaseModel):
    """Authentication status response."""
    
    authenticated: bool
    user: UserInfoResponse | None = None


class ApiResponseMeta(BaseModel):
    """API response metadata."""
    
    request_id: str
    timestamp: str


class UpdateUserMeRequest(BaseModel):
    """Request body for PATCH /me."""

    picture: str | None = None


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
    "secure": True,  # MIP §20 — MUST be True for production deployments
    "samesite": "lax",
    "max_age": 86400,
    "path": "/",
}
_ui_base_url: str = "http://localhost:3000"

# Credential-login dependencies (injected at startup)
_redis_client: Any | None = None  # redis.asyncio.Redis
_session_repository: Any | None = None  # RedisSessionRepository
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
    credential_login_policy_id: str | None = None,
    auth_service_internal_url: str | None = None,
    kc_admin_adapter: Any | None = None,
) -> None:
    """Configure the router with use cases and config."""
    global _authenticate_use_case, _session_use_case, _cookie_config, _ui_base_url
    global _redis_client, _session_repository
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
            url=f"{_ui_base_url}/?auth_error={quote(error_msg, safe='')}",
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
        secure=_cookie_config["secure"],
        samesite=_cookie_config["samesite"],
    )
    
    return response


@router.get("/me", response_model=AuthStatusResponse, response_model_exclude_none=True)
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
            picture=user.picture,
        ),
    )


@router.patch("/me", response_model=AuthStatusResponse, response_model_exclude_none=True)
async def update_current_user(
    body: UpdateUserMeRequest,
    session_id: Annotated[str | None, Cookie(alias="sessionId")] = None,
) -> AuthStatusResponse:
    """
    Update current user's profile attributes.

    Currently supports updating the profile picture (stored in session).
    """
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if _session_repository is None:
        raise HTTPException(status_code=503, detail="Session store unavailable")

    session = await _session_repository.get(session_id)
    if not session or not session.is_valid:
        raise HTTPException(status_code=401, detail="Session not found or expired")

    if body.picture is not None:
        if not (body.picture.startswith("data:image/") or body.picture.startswith("https://")):
            raise HTTPException(status_code=400, detail="picture must be an image data URL or https URL")
        session.user.picture = body.picture
        await _session_repository.save(session)
        logger.info("Updated profile picture for session %s", session_id[:8])

    return AuthStatusResponse(
        authenticated=True,
        user=UserInfoResponse(
            user_id=session.user.user_id,
            email=session.user.email,
            username=session.user.username,
            given_name=session.user.given_name,
            family_name=session.user.family_name,
            user_type=session.user.user_type.value,
            applicant_id=session.user.applicant_id,
            roles=session.user.roles,
            organization_id=session.user.organization_id,
            organization_name=session.user.organization_name,
            onboarding_completed=session.user.onboarding_completed.isoformat() if session.user.onboarding_completed else None,
            picture=session.user.picture,
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
  <title>Login with Marty Badge &mdash; Marty</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box }}
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f5f6fa;
           display:flex; justify-content:center; align-items:center;
           min-height:100vh; margin:0; padding: 1rem }}
    .card {{ background:#fff; border-radius:16px;
             box-shadow:0 4px 24px rgba(0,0,0,.1);
             padding:2.5rem 2rem; max-width:420px; width:100%; text-align:center }}
    .logo {{ width:48px; height:48px; margin:0 auto 1rem; display:block }}
    h1 {{ font-size:1.35rem; margin:0 0 .4rem; color:#1a1a2e }}
    .subtitle {{ color:#666; font-size:.9rem; margin:0 0 1.75rem; line-height:1.5 }}
    /* QR section (shown on desktop) */
    .qr-section img {{ width:220px; height:220px; border:1px solid #e8e8e8;
                      border-radius:10px; display:block; margin:0 auto }}
    .qr-label {{ font-size:.8rem; color:#999; margin:.6rem 0 0 }}
    /* Deep-link section (shown on mobile) */
    .mobile-section {{ display:none }}
    .open-btn {{ display:inline-flex; align-items:center; gap:.5rem;
                 margin-top:.5rem; padding:.75rem 1.5rem; border-radius:10px;
                 background:#1a73e8; color:#fff; text-decoration:none;
                 font-size:1rem; font-weight:600; width:100%;
                 justify-content:center; transition: background .15s }}
    .open-btn:hover {{ background:#1558b0 }}
    .open-btn svg {{ width:20px; height:20px; flex-shrink:0 }}
    /* Secondary toggle link */
    .toggle-link {{ font-size:.82rem; color:#1a73e8; cursor:pointer;
                    text-decoration:underline; margin-top:1rem;
                    display:inline-block; background:none; border:none;
                    padding:0 }}
    .divider {{ border:none; border-top:1px solid #eee; margin:1.5rem 0 }}
    .status {{ margin-top:1.25rem; font-size:.875rem; color:#555;
               min-height:1.4em }}
    .spinner {{ display:inline-block; width:14px; height:14px;
                border:2px solid #ccc; border-top-color:#1a73e8;
                border-radius:50%; animation:spin .8s linear infinite;
                vertical-align:middle; margin-right:6px }}
    @keyframes spin {{ to {{ transform:rotate(360deg) }} }}
    .done {{ color:#27ae60; font-weight:600 }}
    .err  {{ color:#e74c3c }}
    /* Mobile override */
    @media (max-width: 600px) {{
      .qr-section {{ display:none }}
      .mobile-section {{ display:block }}
    }}
  </style>
</head>
<body>
  <div class="card">
    <!-- Icon -->
    <svg class="logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="48" height="48" rx="12" fill="#1a73e8"/>
      <path d="M14 20a10 10 0 0 1 20 0v2h2a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H12
               a2 2 0 0 1-2-2V24a2 2 0 0 1 2-2h2v-2z" fill="white" opacity=".9"/>
      <circle cx="24" cy="29" r="3" fill="#1a73e8"/>
    </svg>

    <h1>Login with Marty Badge</h1>
    <p class="subtitle">Use your Marty wallet to authenticate securely &mdash; no password needed.</p>

    <!-- Desktop: QR code -->
    <div class="qr-section" id="qr-section">
      <img
        src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=8&data={qr_encoded}"
        alt="Scan QR with Marty wallet"
      >
      <p class="qr-label">Scan with the Marty wallet app</p>
      <button class="toggle-link" onclick="showMobile()">On this device? Open in wallet &rsaquo;</button>
    </div>

    <!-- Mobile: deep-link button -->
    <div class="mobile-section" id="mobile-section">
      <a class="open-btn" href="{oid4vp_uri_escaped}" id="wallet-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2"/>
          <path d="M8 21h8M12 17v4"/>
        </svg>
        Open in Wallet App
      </a>
      <p style="font-size:.8rem;color:#999;margin:.75rem 0 0">Tap the button to open your Marty wallet</p>
      <button class="toggle-link" onclick="showQr()">Show QR code instead &rsaquo;</button>
      <div style="margin-top:1rem">
        <div class="qr-section" id="qr-fallback" style="display:none">
          <img
            src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&margin=6&data={qr_encoded}"
            alt="Scan QR with Marty wallet" style="width:180px;height:180px"
          >
        </div>
      </div>
    </div>

    <hr class="divider">
    <div class="status" id="status">
      <span class="spinner"></span> Waiting for wallet response&hellip;
    </div>
  </div>

  <script>
    (function() {{
      // Detect mobile (phones/tablets) and show deep-link instead of QR
      var isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
      if (isMobile) {{
        document.getElementById('qr-section').style.display = 'none';
        document.getElementById('mobile-section').style.display = 'block';
      }}

      function showMobile() {{
        document.getElementById('qr-section').style.display = 'none';
        document.getElementById('mobile-section').style.display = 'block';
      }}
      function showQr() {{
        document.getElementById('qr-fallback').style.display = 'block';
      }}
      window.showMobile = showMobile;
      window.showQr = showQr;

      var nonce = {nonce_json};
      var attempts = 0;
      var max = 180; // 3 min at 1 req/s
      var timer = setInterval(function() {{
        attempts++;
        if (attempts > max) {{
          clearInterval(timer);
          document.getElementById('status').innerHTML =
            '<span class="err">Timed out. <a href="/v1/auth/credential-login">Try again</a></span>';
          return;
        }}
        fetch('/v1/auth/credential-login/status?nonce=' + encodeURIComponent(nonce))
          .then(function(r) {{ return r.json(); }})
          .then(function(d) {{
            if (d.status === 'completed') {{
              clearInterval(timer);
              document.getElementById('status').innerHTML =
                '<span class="done">&#10003; Verified! Redirecting&hellip;</span>';
              window.location.href = d.redirect_to || '/';
            }} else if (d.status === 'failed') {{
              clearInterval(timer);
              document.getElementById('status').innerHTML =
                '<span class="err">Verification failed. <a href="/v1/auth/credential-login">Try again</a></span>';
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

    # Start OID4VP flow via gRPC
    try:
        from marty_proto.v1 import flow_service_pb2, flow_service_pb2_grpc
        flow_stub = flow_service_pb2_grpc.FlowServiceStub(
            request.app.state.flow_grpc_channel
        )
        flow_resp = await flow_stub.StartVerification(
            flow_service_pb2.StartVerificationRequest(
                presentation_policy_id=_credential_login_policy_id,
                callback_url=callback_url,
                user_id="auth-service",
            )
        )
        flow_data = {
            "instance_id": flow_resp.instance_id,
            "request_uri": flow_resp.request_uri,
            "qr_code_data": flow_resp.qr_code_data,
        }
    except Exception as exc:
        logger.error(f"Flow service gRPC error: {exc}")
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
    import html as _html
    html_content = _CREDENTIAL_LOGIN_PAGE.format(
        qr_encoded=qr_encoded,
        oid4vp_uri_escaped=_html.escape(oid4vp_uri, quote=True),
        nonce_json=json.dumps(nonce),
    )
    return HTMLResponse(content=html_content)


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
