"""
Auth Service HTTP Adapter (FastAPI)

FastAPI router providing the HTTP API for the Auth service.
This is the inbound adapter that exposes the use cases via REST.
"""

from __future__ import annotations

import base64
import hashlib
import html as _html
import json
import logging
import os
import secrets
from typing import Annotated, Any
from urllib.parse import parse_qs, quote, urlencode, urlparse

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from marty_common.system_ids import MARTY_OPEN_BADGE_LOGIN_POLICY_ID

from ...application.ports import (
    HandleCallbackCommand,
    InitiateLoginCommand,
    LogoutCommand,
    UserProvisioningPort,
)
from ...application.use_cases import AuthenticateUseCase, SessionUseCase
from ...domain.entities import AuthenticatedUser, ImpersonationContext, Session, UserType
from .applicant_profile_adapter import apply_credential_login_defaults
from .credential_login_enricher import build_credential_login_user
from .oidc_adapter import build_oidc_user_info

try:
    from .keycloak_admin_adapter import KeycloakAdminAdapter, merge_oidc_user_info
except ImportError:
    KeycloakAdminAdapter = None  # type: ignore[assignment,misc]
    merge_oidc_user_info = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


_CREDENTIAL_LOGIN_ASSET_VERSION = "20260519-credential-login-errors-v7"
_DEFAULT_OPEN_BADGE_LOGIN_POLICY_ID = MARTY_OPEN_BADGE_LOGIN_POLICY_ID


_CREDENTIAL_LOGIN_WALLET_CHOICES: tuple[dict[str, str], ...] = (
    {
        "id": "sprucekit",
        "label": "SpruceKit",
        "description": "Selected wallet: SpruceKit.",
        "template_env": "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
        "android_template_env": "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "ios_template_env": "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE",
        "ios_universal_template_env": "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        "android_package_env": "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE",
        "default_template": "{oid4vp_uri}",
        "default_android_template": "intent://authorize?{client_id_param}request_uri={request_uri_encoded}#Intent;scheme=openid4vp;{android_package_param}end",
        "default_ios_template": "{oid4vp_uri}",
        "default_android_package": "com.spruceid.mobilesdkexample",
    },
    {
        "id": "lissi",
        "label": "LISSI Wallet",
        "description": "Selected wallet: LISSI Wallet.",
        "template_env": "CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE",
        "android_template_env": "CREDENTIAL_LOGIN_LISSI_ANDROID_DEEP_LINK_TEMPLATE",
        "ios_template_env": "CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE",
        "ios_universal_template_env": "CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE",
        "android_package_env": "CREDENTIAL_LOGIN_LISSI_ANDROID_PACKAGE",
        "legacy_template_env": "CREDENTIAL_LOGIN_LUCY_DEEP_LINK_TEMPLATE",
        "default_template": "{oid4vp_uri}",
        "default_android_template": "intent://authorize?{client_id_param}request_uri={request_uri_encoded}#Intent;scheme=openid4vp;{android_package_param}end",
        "default_ios_template": "{oid4vp_uri}",
        "default_android_package": "",
        "request_object_compat": "lissi",
    },
)


def _extract_oid4vp_request_uri(oid4vp_uri: str) -> str:
    parsed = urlparse(oid4vp_uri)
    request_uri_values = parse_qs(parsed.query).get("request_uri")
    if request_uri_values:
        return request_uri_values[0]
    return oid4vp_uri


def _with_query_parameter(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[key] = [value]
    return parsed._replace(query=urlencode(query, doseq=True)).geturl()


def _wallet_request_uri(wallet_choice: dict[str, str], request_uri: str, oid4vp_uri: str) -> str:
    normalized_request_uri = _extract_oid4vp_request_uri(request_uri or oid4vp_uri)
    compat = wallet_choice.get("request_object_compat", "").strip().lower()
    if compat:
        normalized_request_uri = _with_query_parameter(normalized_request_uri, "compat", compat)
    return normalized_request_uri


def _wallet_oid4vp_uri(
    oid4vp_uri: str,
    wallet_request_uri: str,
    compat: str = "",
) -> str:
    # Always rebuild the outer openid4vp:// URI via urlencode so that the
    # wallet_request_uri value (which may contain '?' and '=') is properly
    # percent-encoded as a query parameter value.
    rebuilt = _with_query_parameter(oid4vp_uri, "request_uri", wallet_request_uri)
    if compat == "lissi":
        # LISSI's legacy request-object profile uses client_id_scheme=did and
        # therefore signs the JAR with the bare DID. Keep the outer client_id
        # coherent with that signed value when the standard production URI
        # carries the OID4VP 1.0 decentralized_identifier prefix.
        parsed = urlparse(rebuilt)
        client_ids = parse_qs(parsed.query).get("client_id", [])
        if client_ids and client_ids[0].startswith("decentralized_identifier:did:"):
            rebuilt = _with_query_parameter(
                rebuilt,
                "client_id",
                client_ids[0].removeprefix("decentralized_identifier:"),
            )
    return rebuilt


def _credential_login_wallet_template(wallet_choice: dict[str, str], platform: str) -> str:
    if platform == "ios":
        universal_template_env = wallet_choice.get("ios_universal_template_env")
        if universal_template_env and os.environ.get(universal_template_env):
            return os.environ[universal_template_env]

    template_env = wallet_choice.get(f"{platform}_template_env") or wallet_choice["template_env"]
    default_template = wallet_choice.get(f"default_{platform}_template") or wallet_choice["default_template"]
    legacy_template_env = wallet_choice.get("legacy_template_env") if platform == "" else None

    if os.environ.get(template_env):
        return os.environ[template_env]
    if legacy_template_env and os.environ.get(legacy_template_env):
        return os.environ[legacy_template_env]

    return default_template


def _credential_login_android_package(wallet_choice: dict[str, str]) -> str:
    package_env = wallet_choice.get("android_package_env")
    if package_env and os.environ.get(package_env):
        return os.environ[package_env]
    return wallet_choice.get("default_android_package", "")


def _render_credential_login_wallet_link(
    template: str,
    oid4vp_uri: str,
    request_uri: str,
    android_package: str = "",
) -> str:
    normalized_request_uri = _extract_oid4vp_request_uri(request_uri or oid4vp_uri)
    android_package_param = f"package={android_package};" if android_package else ""
    client_ids = parse_qs(urlparse(oid4vp_uri).query).get("client_id", [])
    client_id = client_ids[0] if client_ids else ""
    client_id_encoded = quote(client_id, safe="")
    client_id_param = f"client_id={client_id_encoded}&" if client_id else ""

    try:
        rendered = template.format(
            oid4vp_uri=oid4vp_uri,
            oid4vp_uri_encoded=quote(oid4vp_uri, safe=""),
            request_uri=normalized_request_uri,
            request_uri_encoded=quote(normalized_request_uri, safe=""),
            client_id=client_id,
            client_id_encoded=client_id_encoded,
            client_id_param=client_id_param,
            android_package=android_package,
            android_package_param=android_package_param,
        )
    except Exception as exc:
        logger.warning("Invalid credential-login wallet template %r: %s", template, exc)
        return oid4vp_uri

    return rendered or oid4vp_uri


def _build_credential_login_wallet_options(
    oid4vp_uri: str,
    request_uri: str,
) -> list[dict[str, str]]:
    options: list[dict[str, str]] = []

    for wallet_choice in _CREDENTIAL_LOGIN_WALLET_CHOICES:
        generic_template = _credential_login_wallet_template(wallet_choice, "")
        android_template = _credential_login_wallet_template(wallet_choice, "android")
        ios_template = _credential_login_wallet_template(wallet_choice, "ios")
        android_package = _credential_login_android_package(wallet_choice)
        compat = wallet_choice.get("request_object_compat", "").strip().lower()
        wallet_request_uri = _wallet_request_uri(wallet_choice, request_uri, oid4vp_uri)
        wallet_oid4vp_uri = _wallet_oid4vp_uri(
            oid4vp_uri,
            wallet_request_uri,
            compat,
        )
        options.append(
            {
                "id": wallet_choice["id"],
                "label": wallet_choice["label"],
                "description": wallet_choice["description"],
                "href": _render_credential_login_wallet_link(
                    generic_template,
                    oid4vp_uri=wallet_oid4vp_uri,
                    request_uri=wallet_request_uri,
                ),
                "android_href": _render_credential_login_wallet_link(
                    android_template,
                    oid4vp_uri=wallet_oid4vp_uri,
                    request_uri=wallet_request_uri,
                    android_package=android_package,
                ),
                "ios_href": _render_credential_login_wallet_link(
                    ios_template,
                    oid4vp_uri=wallet_oid4vp_uri,
                    request_uri=wallet_request_uri,
                ),
            }
        )

    return options


def _render_credential_login_wallet_option_tags(
    wallet_options: list[dict[str, str]],
) -> str:
    rendered_options: list[str] = []

    for index, wallet_option in enumerate(wallet_options):
        selected_attr = " selected" if index == 0 else ""
        rendered_options.append(
            """
            <option value="{value}" data-link="{href}" data-android-link="{android_href}" data-ios-link="{ios_href}" data-label="{label}" data-description="{description}"{selected_attr}>{label}</option>
            """.format(
                value=_html.escape(wallet_option["id"], quote=True),
                href=_html.escape(wallet_option["href"], quote=True),
                android_href=_html.escape(wallet_option["android_href"], quote=True),
                ios_href=_html.escape(wallet_option["ios_href"], quote=True),
                label=_html.escape(wallet_option["label"], quote=True),
                description=_html.escape(wallet_option["description"], quote=True),
                selected_attr=selected_attr,
            ).strip()
        )

    return "\n".join(rendered_options)


def _render_credential_login_page(
    *,
    nonce: str,
    flow_instance_id: str,
    qr_encoded: str,
    oid4vp_uri: str,
    request_uri: str,
) -> str:
    wallet_options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=request_uri,
    )
    default_wallet = wallet_options[0] if wallet_options else {
        "label": "Wallet App",
        "description": "Open the login request in your wallet.",
        "href": oid4vp_uri,
    }
    qr_encoded_value = quote(default_wallet.get("href") or oid4vp_uri, safe="") if wallet_options else qr_encoded
    dc_api_request_url = ""
    dc_api_submit_url = ""
    if flow_instance_id:
        encoded_instance_id = quote(flow_instance_id, safe="")
        dc_api_request_url = f"/v1/flows/instances/{encoded_instance_id}/request?transport=dc_api"
        dc_api_submit_url = f"/v1/flows/instances/{encoded_instance_id}/submit/dc-api"

    return _CREDENTIAL_LOGIN_PAGE.format(
        qr_encoded=qr_encoded_value,
        oid4vp_uri_escaped=_html.escape(default_wallet["href"], quote=True),
        nonce_attr=_html.escape(nonce, quote=True),
        dc_api_request_url_attr=_html.escape(dc_api_request_url, quote=True),
        dc_api_submit_url_attr=_html.escape(dc_api_submit_url, quote=True),
        dc_api_protocol_attr=_html.escape("openid4vp-v1-signed", quote=True),
        nonce_json=json.dumps(nonce),
        asset_version=_html.escape(_CREDENTIAL_LOGIN_ASSET_VERSION, quote=True),
        wallet_option_tags=_render_credential_login_wallet_option_tags(wallet_options),
        wallet_help_text=_html.escape(default_wallet["description"], quote=True),
    )


def _render_credential_login_action_link(
    *,
    href: str,
    label: str,
    primary: bool,
) -> str:
    css_class = "open-btn" if primary else "secondary-btn"
    return (
        f'<a class="{css_class}" href="{_html.escape(href, quote=True)}">'
        f'{_html.escape(label)}</a>'
    )


def _render_credential_login_error_page(
    *,
    title: str,
    message: str,
    primary_action_href: str,
    primary_action_label: str,
    secondary_action_href: str = "",
    secondary_action_label: str = "",
    operator_details: str = "",
) -> str:
    actions = [
        _render_credential_login_action_link(
            href=primary_action_href,
            label=primary_action_label,
            primary=True,
        )
    ]
    if secondary_action_href and secondary_action_label:
        actions.append(
            _render_credential_login_action_link(
                href=secondary_action_href,
                label=secondary_action_label,
                primary=False,
            )
        )

    operator_details_html = ""
    if operator_details:
        operator_details_html = (
            '<details class="notice">'
            '<summary>Operator details</summary>'
            f'<p>{_html.escape(operator_details)}</p>'
            '</details>'
        )

    return _CREDENTIAL_LOGIN_ERROR_PAGE.format(
        title=_html.escape(title),
        message=_html.escape(message),
        asset_version=_html.escape(_CREDENTIAL_LOGIN_ASSET_VERSION, quote=True),
        actions_html="\n".join(actions),
        operator_details_html=operator_details_html,
    )


def _credential_login_unavailable_response(
    request: Request,
    *,
    title: str,
    message: str,
    operator_details: str = "",
    allow_retry: bool = False,
) -> HTMLResponse:
    referer = (request.headers.get("referer") or "").strip()
    back_url = _sanitize_redirect_uri(referer, _ui_base_url) if referer else ""
    home_url = _ui_base_url or "/"

    if allow_retry:
        primary_action_href = str(request.url.path or "/v1/auth/credential-login")
        primary_action_label = "Try again"
        secondary_action_href = back_url or home_url
        secondary_action_label = "Back to sign in" if back_url else "Return to ElevenID"
    else:
        primary_action_href = back_url or home_url
        primary_action_label = "Back to sign in" if back_url else "Return to ElevenID"
        secondary_action_href = home_url if back_url else ""
        secondary_action_label = "Return to ElevenID" if back_url else ""

    return HTMLResponse(
        content=_render_credential_login_error_page(
            title=title,
            message=message,
            primary_action_href=primary_action_href,
            primary_action_label=primary_action_label,
            secondary_action_href=secondary_action_href,
            secondary_action_label=secondary_action_label,
            operator_details=operator_details,
        ),
        status_code=503,
        headers={"Cache-Control": "no-store, max-age=0"},
    )

# Create router with versioned prefix
router = APIRouter(prefix="/v1/auth", tags=["authentication"])


# =============================================================================
# Response Models
# =============================================================================

class ImpersonationInfoResponse(BaseModel):
    """Admin impersonation session details surfaced to the UI."""

    active: bool = True
    admin_user_id: str | None = None
    admin_username: str | None = None
    admin_email: str | None = None
    admin_display_name: str | None = None
    target_user_id: str | None = None
    target_email: str | None = None
    organization_id: str | None = None
    organization_name: str | None = None
    started_at: str | None = None
    launch_mode: str | None = None


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
    default_organization_id: str | None = None
    default_organization_name: str | None = None
    organizations: list[dict[str, Any]] = Field(default_factory=list)
    organization_context_unavailable: bool = False
    organization_context_error: str | None = None
    onboarding_completed: str | None = None
    picture: str | None = None
    impersonation: ImpersonationInfoResponse | None = None
    did_subject: str | None = None  # MIP §5 — DID from credential login


class AuthStatusResponse(BaseModel):
    """Authentication status response."""
    
    authenticated: bool
    user: UserInfoResponse | None = None


def _user_info_response(user: AuthenticatedUser) -> UserInfoResponse:
    return UserInfoResponse(
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
        organization=user.organization,
        default_organization_id=user.default_organization_id,
        default_organization_name=user.default_organization_name,
        organizations=user.organizations,
        organization_context_unavailable=user.organization_context_unavailable,
        organization_context_error=user.organization_context_error,
        onboarding_completed=user.onboarding_completed.isoformat() if user.onboarding_completed else None,
        picture=user.picture,
        impersonation=ImpersonationInfoResponse(**user.impersonation.to_dict()) if user.impersonation else None,
        did_subject=user.did_subject,
    )


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
_issuance_service_url: str = os.environ.get("ISSUANCE_SERVICE_URL", "http://issuance:8005")
_canvas_lti_session_ttl_seconds = int(
    os.environ.get(
        "CANVAS_LTI_SESSION_TTL_SECONDS",
        os.environ.get("SESSION_TTL_SECONDS", "86400"),
    )
)
_kc_admin_adapter: Any | None = None  # KeycloakAdminAdapter | None
_user_provisioning: UserProvisioningPort | None = None
_applicant_profile_provisioner: Any | None = None
_impersonation_handoff_cookie_name = "marty_impersonation_handoff"
_credential_login_require_existing_keycloak_user = os.environ.get(
    "CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER", "false"
).lower() in {"1", "true", "yes", "on"}
_credential_login_create_users = os.environ.get(
    "CREDENTIAL_LOGIN_CREATE_USERS", "false"
).lower() in {"1", "true", "yes", "on"}

# Redis key prefixes for credential-login state
_PENDING_KEY = "marty:cred_login:pending:"
_COMPLETE_KEY = "marty:cred_login:complete:"
_PENDING_TTL = 900   # 15 minutes
_COMPLETE_TTL = 300  # 5 minutes (consumed once)


def _credential_login_failure_reason_code(reason: str | None) -> str:
    normalized_reason = (reason or "").strip()
    lowered_reason = normalized_reason.lower()

    if normalized_reason in {
        "keycloak_user_not_found",
        "keycloak_user_not_eligible",
        "keycloak_admin_unavailable",
    }:
        return normalized_reason
    if any(
        marker in lowered_reason
        for marker in (
            "does not match any trust source issuer identifier",
            "not in trust profile allowed_issuers",
            "explicitly denied by trust profile",
        )
    ):
        return "issuer_not_trusted"
    if any(
        marker in lowered_reason
        for marker in (
            "missing email claim",
            "missing email",
            "no email in verified_claims",
        )
    ):
        return "missing_email_claim"
    if "revocation status was not checked" in lowered_reason:
        return "revocation_not_checked"
    if "credential is revoked" in lowered_reason:
        return "credential_revoked"
    if any(
        marker in lowered_reason
        for marker in (
            "policy service unavailable",
            "temporarily unavailable",
            "trust profile validation failed",
            "could not be loaded",
        )
    ):
        return "verification_service_unavailable"
    if any(
        marker in lowered_reason
        for marker in (
            "did resolution failed",
            "unsupported credential format",
            "malformed",
            "invalid credential",
            "invalid presentation",
        )
    ):
        return "credential_payload_invalid"
    return "verification_failed"


def _credential_login_failure_message(reason_code: str) -> str:
    return {
        "issuer_not_trusted": (
            "This badge was issued by an issuer that ElevenID does not trust for sign-in on this site."
        ),
        "missing_email_claim": "This badge is missing the email claim required for sign-in.",
        "revocation_not_checked": "We could not confirm this badge is still active.",
        "credential_revoked": "This badge has been revoked and can no longer be used for sign-in.",
        "verification_service_unavailable": (
            "Open Badge sign-in is temporarily unavailable. Please try again in a moment."
        ),
        "credential_payload_invalid": "We could not verify the badge that was presented.",
        "keycloak_user_not_found": (
            "We verified the badge, but no ElevenID account matches the email in it."
        ),
        "keycloak_user_not_eligible": (
            "We verified the badge, but the matching ElevenID account is not eligible for Open Badge sign-in."
        ),
        "keycloak_admin_unavailable": (
            "We verified the badge, but account lookup is temporarily unavailable."
        ),
    }.get(reason_code, "We could not verify this Open Badge for sign-in.")


def _credential_login_failure_detail(reason_code: str, reason: str | None) -> str | None:
    normalized_reason = (reason or "").strip()
    if not normalized_reason or normalized_reason == reason_code:
        return None
    if reason_code in {
        "keycloak_user_not_found",
        "keycloak_user_not_eligible",
        "keycloak_admin_unavailable",
    }:
        return None
    return normalized_reason


def _credential_login_failure_payload(reason: str | None) -> dict[str, Any]:
    normalized_reason = (reason or "").strip()
    reason_code = _credential_login_failure_reason_code(normalized_reason)
    payload: dict[str, Any] = {
        "status": "failed",
        "reason_code": reason_code,
        "message": _credential_login_failure_message(reason_code),
    }
    if normalized_reason:
        payload["reason"] = normalized_reason
    detail = _credential_login_failure_detail(reason_code, normalized_reason)
    if detail:
        payload["detail"] = detail
    return payload


def _coerce_credential_login_failure_payload(data: dict[str, Any]) -> dict[str, Any]:
    if data.get("reason_code") and data.get("message"):
        payload = dict(data)
        payload.setdefault("status", "failed")
        return payload

    payload = _credential_login_failure_payload(
        data.get("reason") or data.get("detail") or data.get("message")
    )
    if data.get("detail") and not payload.get("detail"):
        payload["detail"] = str(data["detail"])
    return payload


def _credential_login_failure_redirect_url(data: dict[str, Any]) -> str:
    failure_payload = _coerce_credential_login_failure_payload(data)
    query_params = {
        "auth_error": failure_payload.get("message") or "Verification failed",
    }
    if failure_payload.get("reason_code"):
        query_params["auth_error_code"] = failure_payload["reason_code"]
    if failure_payload.get("detail"):
        query_params["auth_error_detail"] = failure_payload["detail"]
    return f"{_ui_base_url}/?{urlencode(query_params)}"


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


def _is_same_origin_root_url(url: str, ui_base_url: str) -> bool:
    try:
        parsed = urlparse(url)
        base = urlparse(ui_base_url)
    except Exception:
        return False

    return (
        parsed.scheme == base.scheme
        and parsed.netloc == base.netloc
        and (parsed.path or "/") == "/"
        and not parsed.query
        and not parsed.fragment
    )


def _resolve_post_auth_redirect(redirect_uri: str | None, ui_base_url: str) -> str:
    """Resolve the final post-auth path within the UI.

    Successful sign-in should land in the authenticated console experience when
    the original target was the public root. Sending users back to `/` makes the
    session look like it failed because the marketing homepage is largely the
    same for authenticated and unauthenticated visitors.
    """
    sanitized = _sanitize_redirect_uri(redirect_uri, ui_base_url)

    if sanitized == "/" or _is_same_origin_root_url(sanitized, ui_base_url):
        return "/console"

    return sanitized


def _build_ui_redirect_url(redirect_uri: str | None, ui_base_url: str) -> str:
    resolved = _resolve_post_auth_redirect(redirect_uri, ui_base_url)

    if resolved.startswith("/"):
        return f"{ui_base_url.rstrip('/')}{resolved}"

    return resolved


def _first_non_empty_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _lti_lis_claims(raw_claims: dict[str, Any]) -> dict[str, Any]:
    for key in (
        "https://purl.imsglobal.org/spec/lti/claim/lis",
        "lis",
    ):
        value = raw_claims.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _split_canvas_lti_name(name: str | None) -> tuple[str | None, str | None]:
    normalized = (name or "").strip()
    if not normalized:
        return None, None
    parts = normalized.split()
    if len(parts) == 1:
        return parts[0], None
    return parts[0], " ".join(parts[1:])


def _email_local_part(email: str | None) -> str | None:
    normalized = (email or "").strip()
    if "@" not in normalized:
        return None
    local_part = normalized.split("@", 1)[0].strip()
    return local_part or None


def _build_canvas_lti_user(session_payload: dict[str, Any]) -> AuthenticatedUser:
    """Create a constrained applicant identity from a verified Canvas LTI launch."""
    verified_launch = session_payload.get("verified_launch")
    if not isinstance(verified_launch, dict):
        verified_launch = {}

    learner = verified_launch.get("learner_identity")
    if not isinstance(learner, dict):
        learner = {}
    raw_claims = verified_launch.get("raw_claims")
    if not isinstance(raw_claims, dict):
        raw_claims = {}
    lis_claims = _lti_lis_claims(raw_claims)

    issuer = _first_non_empty_string(
        verified_launch.get("issuer"),
        raw_claims.get("iss"),
        session_payload.get("canvas_account_id"),
        "canvas",
    )
    subject = _first_non_empty_string(
        verified_launch.get("subject"),
        learner.get("subject"),
        raw_claims.get("sub"),
        learner.get("id"),
        session_payload.get("learner_key"),
    )
    if not subject:
        raise ValueError("Canvas LTI session is missing a learner subject")

    digest = hashlib.sha256(f"{issuer}|{subject}".encode("utf-8")).hexdigest()
    email = _first_non_empty_string(
        learner.get("email"),
        raw_claims.get("email"),
        raw_claims.get("lis_person_contact_email_primary"),
        lis_claims.get("person_contact_email_primary"),
    )
    if not email:
        email = f"canvas-{digest[:16]}@canvas.lti.local"

    display_name = _first_non_empty_string(
        learner.get("name"),
        raw_claims.get("name"),
        raw_claims.get("lis_person_name_full"),
        lis_claims.get("person_name_full"),
        session_payload.get("learner_display_name"),
    )
    inferred_given_name, inferred_family_name = _split_canvas_lti_name(display_name)
    given_name = _first_non_empty_string(
        learner.get("given_name"),
        raw_claims.get("given_name"),
        raw_claims.get("lis_person_name_given"),
        lis_claims.get("person_name_given"),
        inferred_given_name,
    )
    family_name = _first_non_empty_string(
        learner.get("family_name"),
        raw_claims.get("family_name"),
        raw_claims.get("lis_person_name_family"),
        lis_claims.get("person_name_family"),
        inferred_family_name,
    )

    return AuthenticatedUser(
        user_id=f"canvas-lti-{digest[:32]}",
        email=email,
        username=_first_non_empty_string(
            learner.get("preferred_username"),
            raw_claims.get("preferred_username"),
            learner.get("login_id"),
            raw_claims.get("login_id"),
            raw_claims.get("lis_person_sourcedid"),
            lis_claims.get("person_sourcedid"),
            _email_local_part(email),
            display_name,
            subject,
            f"canvas-{digest[:12]}",
        ),
        given_name=given_name,
        family_name=family_name,
        user_type=UserType.APPLICANT,
        roles=["applicant", "canvas_lti_learner"],
        organization_id=_first_non_empty_string(session_payload.get("organization_id")),
        organization_name="Canvas learner organization",
        organization=None,
    )


async def _fetch_canvas_lti_experience_session(state: str) -> dict[str, Any]:
    normalized_state = (state or "").strip()
    if not normalized_state:
        raise HTTPException(status_code=400, detail="Canvas LTI state is required")

    url = (
        f"{_issuance_service_url.rstrip('/')}"
        f"/v1/integrations/canvas/lti/experience-sessions/{quote(normalized_state, safe='')}"
    )
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            response = await client.get(url)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Canvas LTI session lookup timed out") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Canvas LTI session lookup failed") from exc

    if response.status_code == 404:
        raise HTTPException(status_code=404, detail="Canvas LTI session not found")
    if response.status_code >= 500:
        raise HTTPException(status_code=502, detail="Canvas LTI session service failed")
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail="Canvas LTI session is invalid")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Canvas LTI session response was invalid") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Canvas LTI session response was invalid")
    return payload


async def _fetch_current_canvas_lti_experience_session(token: str) -> dict[str, Any]:
    normalized = str(token or "").strip()
    if not normalized:
        raise HTTPException(status_code=401, detail="Canvas LTI session token is required")
    url = (
        f"{_issuance_service_url.rstrip('/')}"
        "/v1/integrations/canvas/lti/experience-sessions/current"
    )
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            response = await client.get(
                url,
                headers={"Authorization": f"Bearer {normalized}"},
                follow_redirects=False,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Canvas LTI session lookup timed out") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Canvas LTI session lookup failed") from exc
    if response.status_code in {401, 404}:
        raise HTTPException(status_code=401, detail="Canvas LTI session is invalid or expired")
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Canvas LTI session service failed")
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Canvas LTI session response was invalid") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Canvas LTI session response was invalid")
    return payload


def _normalized_origin(origin: str | None) -> str | None:
    if not origin:
        return None

    try:
        parsed = urlparse(origin.strip())
    except Exception:
        return None

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _allowed_ui_base_urls() -> set[str]:
    allowed = {_normalized_origin(_ui_base_url)}
    for env_name in (
        "UI_ADDITIONAL_BASE_URLS",
        "AUTH_ADDITIONAL_UI_BASE_URLS",
        "CORS_ORIGINS",
    ):
        for origin in _split_csv(os.environ.get(env_name)):
            allowed.add(_normalized_origin(origin))
    return {origin for origin in allowed if origin}


def _origin_with_matching_host(origin: str | None, allowed_origins: set[str]) -> str | None:
    if not origin:
        return None

    try:
        request_netloc = urlparse(origin).netloc.lower()
    except Exception:
        return None

    if not request_netloc:
        return None

    for allowed_origin in sorted(allowed_origins):
        try:
            allowed_parsed = urlparse(allowed_origin)
        except Exception:
            continue
        if allowed_parsed.netloc.lower() == request_netloc:
            return allowed_origin

    return None


def _request_origin(request: Request) -> str | None:
    forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if not forwarded_host:
        return None

    host = forwarded_host.split(",", 1)[0].strip()
    if not host:
        return None

    forwarded_proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    proto = forwarded_proto.split(",", 1)[0].strip().lower()
    if proto not in {"http", "https"}:
        proto = "https"

    return _normalized_origin(f"{proto}://{host}")


def _request_ui_base_url(request: Request) -> str:
    request_origin = _request_origin(request)
    allowed_origins = _allowed_ui_base_urls()
    if request_origin:
        if request_origin in allowed_origins:
            return request_origin

        matching_origin = _origin_with_matching_host(request_origin, allowed_origins)
        if matching_origin:
            logger.info(
                "Normalizing auth request origin %s to trusted UI origin %s",
                request_origin,
                matching_origin,
            )
            return matching_origin

        logger.warning(
            "Ignoring untrusted auth request origin: %s; allowed UI origins: %s",
            request_origin,
            ", ".join(sorted(allowed_origins)) or "<none>",
        )

    return _ui_base_url


def _oidc_callback_url(ui_base_url: str) -> str:
    return f"{ui_base_url.rstrip('/')}/v1/auth/callback"


def _decode_jwt_claims(token: str | None) -> dict[str, Any]:
    """Decode JWT claims without signature verification."""
    if not token:
        return {}

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}

        payload = parts[1]
        padding = (-len(payload)) % 4
        if padding:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8")
        claims = json.loads(decoded)
        return claims if isinstance(claims, dict) else {}
    except Exception:
        logger.debug("Failed to decode JWT claims for impersonation detection", exc_info=True)
        return {}


def _decode_impersonation_handoff(raw_cookie: str | None) -> dict[str, Any] | None:
    """Decode the short-lived impersonation handoff cookie set before Keycloak redirect."""
    if not raw_cookie:
        return None

    try:
        padding = (-len(raw_cookie)) % 4
        encoded = raw_cookie + ("=" * padding)
        payload = base64.urlsafe_b64decode(encoded.encode("utf-8")).decode("utf-8")
        data = json.loads(payload)
        return data if isinstance(data, dict) else None
    except Exception:
        logger.debug("Failed to decode impersonation handoff cookie", exc_info=True)
        return None


def _get_native_impersonator_claims(claims: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract impersonator identity from Keycloak session-note mappers when available."""
    impersonator = claims.get("impersonator")
    if isinstance(impersonator, dict):
        return impersonator.get("id"), impersonator.get("username")

    return (
        claims.get("IMPERSONATOR_ID") or claims.get("impersonator_id"),
        claims.get("IMPERSONATOR_USERNAME") or claims.get("impersonator_username"),
    )


def _build_session_impersonation(
    session: Session,
    request: Request,
) -> ImpersonationContext | None:
    """
    Resolve impersonation context for the session.

    Prefers native Keycloak impersonator session-note claims when available and
    falls back to the short-lived handoff cookie we set before redirecting to
    Keycloak's native impersonation endpoint.
    """
    claims = _decode_jwt_claims(session.id_token)
    native_admin_user_id, native_admin_username = _get_native_impersonator_claims(claims)
    handoff = _decode_impersonation_handoff(request.cookies.get(_impersonation_handoff_cookie_name))

    if handoff:
        target_user_id = handoff.get("target_user_id")
        target_email = handoff.get("target_email")
        matches_target = (
            (target_user_id and target_user_id == session.user.user_id) or
            (target_email and target_email.lower() == session.user.email.lower())
        )

        if matches_target:
            return ImpersonationContext(
                active=True,
                admin_user_id=native_admin_user_id or handoff.get("admin_user_id"),
                admin_username=native_admin_username or handoff.get("admin_username"),
                admin_email=handoff.get("admin_email"),
                admin_display_name=handoff.get("admin_display_name"),
                target_user_id=session.user.user_id,
                target_email=session.user.email,
                organization_id=handoff.get("organization_id") or session.user.organization_id,
                organization_name=handoff.get("organization_name") or session.user.organization_name,
                started_at=handoff.get("started_at"),
                launch_mode=handoff.get("launch_mode"),
            )

    if native_admin_user_id or native_admin_username:
        return ImpersonationContext(
            active=True,
            admin_user_id=native_admin_user_id,
            admin_username=native_admin_username,
            target_user_id=session.user.user_id,
            target_email=session.user.email,
            organization_id=session.user.organization_id,
            organization_name=session.user.organization_name,
        )

    return None


def configure_auth_router(
    authenticate_use_case: AuthenticateUseCase,
    session_use_case: SessionUseCase,
    cookie_config: dict[str, Any] | None = None,
    ui_base_url: str | None = None,
    redis_client: Any | None = None,
    session_repository: Any | None = None,
    credential_login_policy_id: str | None = None,
    auth_service_internal_url: str | None = None,
    issuance_service_url: str | None = None,
    kc_admin_adapter: Any | None = None,
    user_provisioning: UserProvisioningPort | None = None,
    applicant_profile_provisioner: Any | None = None,
) -> None:
    """Configure the router with use cases and config."""
    global _authenticate_use_case, _session_use_case, _cookie_config, _ui_base_url
    global _redis_client, _session_repository
    global _credential_login_policy_id, _auth_service_internal_url, _issuance_service_url, _kc_admin_adapter
    global _user_provisioning, _applicant_profile_provisioner
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
    if issuance_service_url:
        _issuance_service_url = issuance_service_url
    if kc_admin_adapter is not None:
        _kc_admin_adapter = kc_admin_adapter
    if user_provisioning is not None:
        _user_provisioning = user_provisioning
    if applicant_profile_provisioner is not None:
        _applicant_profile_provisioner = applicant_profile_provisioner


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
    request_ui_base_url = _request_ui_base_url(request)
    safe_redirect = _sanitize_redirect_uri(redirect_uri, request_ui_base_url)
    result = await use_case.initiate_login(
        InitiateLoginCommand(
            redirect_uri=safe_redirect,
            oidc_redirect_uri=_oidc_callback_url(request_ui_base_url),
        )
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
    request_ui_base_url = _request_ui_base_url(request)
    safe_redirect = _sanitize_redirect_uri(redirect_uri, request_ui_base_url)
    result = await use_case.initiate_registration(
        InitiateLoginCommand(
            redirect_uri=safe_redirect,
            oidc_redirect_uri=_oidc_callback_url(request_ui_base_url),
        )
    )
    
    logger.info("Redirecting to OIDC provider for registration")
    return RedirectResponse(url=result.authorization_url, status_code=302)


async def _create_canvas_lti_auth_session(
    request: Request,
    session_payload: dict[str, Any],
) -> Session:
    """Create the constrained applicant session for a verified LTI experience."""
    if _session_repository is None:
        raise HTTPException(status_code=503, detail="Session store not available")

    try:
        user = _build_canvas_lti_user(session_payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user = apply_credential_login_defaults(user)
    if user.organization_id and not user.organization:
        user.organization = {
            user.organization_id: {
                "name": user.organization_name or "ElevenID LLC",
                "source": "canvas_lti",
            }
        }

    if _applicant_profile_provisioner is not None:
        try:
            applicant_id = await _applicant_profile_provisioner(user)
            if applicant_id:
                user.applicant_id = applicant_id
        except Exception as exc:
            logger.warning(
                "Applicant profile provisioning failed during Canvas LTI login for %s: %s",
                user.email,
                exc,
            )

    session = Session.create(
        user=user,
        ttl_seconds=_canvas_lti_session_ttl_seconds,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await _session_repository.save(session)
    logger.info(
        "Canvas LTI session finalized: org=%s user=%s session=%s...",
        user.organization_id,
        user.user_id,
        session.session_id[:8],
    )
    return session


def _set_auth_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=_cookie_config["key"],
        value=session_id,
        httponly=_cookie_config["httponly"],
        secure=_cookie_config["secure"],
        samesite=_cookie_config["samesite"],
        max_age=_cookie_config["max_age"],
        path=_cookie_config["path"],
    )


@router.get("/canvas-lti/finalize")
async def canvas_lti_legacy_finalize() -> None:
    """Reject the removed state-in-query Canvas authentication handoff."""
    raise HTTPException(
        status_code=410,
        detail="Canvas LTI state finalization is no longer supported",
    )


@router.post("/canvas-lti/finalize")
async def canvas_lti_finalize(request: Request) -> JSONResponse:
    """Finalize authentication using the short-lived bearer experience session."""
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Canvas LTI session token is required")

    session_payload = await _fetch_current_canvas_lti_experience_session(token.strip())
    session = await _create_canvas_lti_auth_session(request, session_payload)
    response = JSONResponse(
        {
            "authenticated": True,
            "expires_in": _canvas_lti_session_ttl_seconds,
        }
    )
    _set_auth_session_cookie(response, session.session_id)
    return response


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
    request_ui_base_url = _request_ui_base_url(request)
    if error:
        logger.warning(f"OIDC error callback: {error} - {error_description}")
        
        # If user is already authenticated as different user, suggest logout
        if error in ("different_user_authenticated", "already_logged_in"):
            return RedirectResponse(
                url=f"{request_ui_base_url}/?auth_error=already_authenticated&message=Please+logout+first+to+login+as+a+different+user",
                status_code=302,
            )
        
        error_msg = error_description or error
        return RedirectResponse(
            url=f"{request_ui_base_url}/?auth_error={quote(error_msg, safe='')}",
            status_code=302,
        )
    
    # Validate required parameters
    if not code or not state:
        logger.warning("Callback missing code or state parameter")
        return RedirectResponse(
            url=f"{request_ui_base_url}/?auth_error=Missing+authentication+parameters",
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
        
        # Resolve redirect_uri: send root logins to the authenticated console entry
        # so social/OIDC sign-ins don't appear to "bounce" back to the home page.
        raw_redirect = result.redirect_uri
        resolved_redirect = _resolve_post_auth_redirect(raw_redirect, request_ui_base_url)
        redirect_uri = _build_ui_redirect_url(raw_redirect, request_ui_base_url)
        
        logger.info(
            "Callback redirect: raw=%r resolved=%r final=%r ui_base=%r",
            raw_redirect, resolved_redirect, redirect_uri, request_ui_base_url,
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

        impersonation = _build_session_impersonation(result.session, request)
        if impersonation is not None and _session_repository is not None:
            result.session.user.impersonation = impersonation
            await _session_repository.save(result.session)

        response.delete_cookie(
            key=_impersonation_handoff_cookie_name,
            path="/",
            secure=_cookie_config["secure"],
            samesite=_cookie_config["samesite"],
        )
        
        logger.info(f"User {result.session.user.email} authenticated successfully")
        return response
        
    except ValueError as e:
        logger.warning(f"Authentication failed: {e}")
        return RedirectResponse(
            url=f"{request_ui_base_url}/?auth_error=Session+expired.+Please+try+again.",
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
    response.delete_cookie(
        key=_impersonation_handoff_cookie_name,
        path="/",
        secure=_cookie_config["secure"],
        samesite=_cookie_config["samesite"],
    )
    
    return response


@router.get("/me", response_model=AuthStatusResponse, response_model_exclude_none=True)
async def get_current_user(
    response: Response,
    user: AuthenticatedUser | None = Depends(get_current_session),
) -> AuthStatusResponse:
    """
    Get current authenticated user.
    
    Returns authentication status and user info if authenticated.
    """
    response.headers["Cache-Control"] = "no-store, max-age=0"

    if not user:
        return AuthStatusResponse(authenticated=False, user=None)
    
    return AuthStatusResponse(
        authenticated=True,
        user=_user_info_response(user),
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
        user=_user_info_response(session.user),
    )


# =============================================================================
# Credential Login (Open Badge / OID4VP) Endpoints
# =============================================================================

_CREDENTIAL_LOGIN_CSS = """\
*, *::before, *::after { box-sizing: border-box }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: #f5f6fa;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  margin: 0;
  padding: 1rem;
}
.card {
  background: #fff;
  border-radius: 16px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, .1);
  padding: 2.5rem 2rem;
  max-width: 420px;
  width: 100%;
  text-align: center;
}
.logo { width: 48px; height: 48px; margin: 0 auto 1rem; display: block }
h1 { font-size: 1.35rem; margin: 0 0 .4rem; color: #1a1a2e }
.subtitle { color: #666; font-size: .9rem; margin: 0 0 1.75rem; line-height: 1.5 }
.qr-section img {
  width: 220px;
  height: 220px;
  border: 1px solid #e8e8e8;
  border-radius: 10px;
  display: block;
  margin: 0 auto;
}
.qr-label { font-size: .8rem; color: #999; margin: .6rem 0 0 }
.mobile-section { display: none }
.open-btn {
  display: inline-flex;
  align-items: center;
  gap: .5rem;
  margin-top: .5rem;
  padding: .75rem 1.5rem;
  border-radius: 10px;
  background: #1a73e8;
  color: #fff;
  text-decoration: none;
  font-size: 1rem;
  font-weight: 600;
  width: 100%;
  justify-content: center;
  transition: background .15s;
}
.open-btn:hover { background: #1558b0 }
.open-btn svg { width: 20px; height: 20px; flex-shrink: 0 }
.wallet-controls { display: grid; gap: .75rem; margin: 0 0 1rem }
.wallet-picker { text-align: left }
.wallet-label { display: block; font-size: .82rem; font-weight: 600; color: #555; margin-bottom: .4rem }
.wallet-select {
    width: 100%;
    border: 1px solid #d0d7e2;
    border-radius: 10px;
    padding: .75rem .9rem;
    font-size: .95rem;
    background: #fff;
    color: #1a1a2e;
}
.toggle-link {
  font-size: .82rem;
  color: #1a73e8;
  cursor: pointer;
  text-decoration: underline;
  margin-top: 1rem;
  display: inline-block;
  background: none;
  border: none;
  padding: 0;
}
.divider { border: none; border-top: 1px solid #eee; margin: 1.5rem 0 }
.status { margin-top: 1.25rem; font-size: .875rem; color: #555; min-height: 1.4em }
.status-detail {
    margin-top: .55rem;
    color: #64748b;
    font-size: .82rem;
    line-height: 1.45;
}
.status-detail a { color: #1a73e8 }
.status-eyebrow {
    display: inline-block;
    margin: 0 0 .75rem;
    color: #c0392b;
    font-size: .82rem;
    font-weight: 700;
    letter-spacing: .02em;
    text-transform: uppercase;
}
.spinner {
  display: inline-block;
  width: 14px;
  height: 14px;
  border: 2px solid #ccc;
  border-top-color: #1a73e8;
  border-radius: 50%;
  animation: spin .8s linear infinite;
  vertical-align: middle;
  margin-right: 6px;
}
.mobile-help { font-size: .8rem; color: #999; margin: .75rem 0 0 }
.qr-fallback { display: none; margin-top: 1rem }
.qr-small { width: 180px !important; height: 180px !important }
.action-group { display: grid; gap: .75rem; margin-top: 1.5rem }
.secondary-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: .5rem;
    width: 100%;
    padding: .75rem 1.5rem;
    border-radius: 10px;
    border: 1px solid #d0d7e2;
    background: #fff;
    color: #1a1a2e;
    text-decoration: none;
    font-size: 1rem;
    font-weight: 600;
    transition: background .15s, border-color .15s;
}
.secondary-btn:hover { background: #f8fafc; border-color: #b9c4d4 }
.notice {
    margin-top: 1.25rem;
    padding: .9rem 1rem;
    border: 1px solid #dbe4f0;
    border-radius: 12px;
    background: #f8fafc;
    color: #334155;
    text-align: left;
    font-size: .85rem;
    line-height: 1.5;
}
.notice summary {
    cursor: pointer;
    color: #1a1a2e;
    font-weight: 700;
}
.notice p { margin: .75rem 0 0 }
code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .85em;
    background: #eef2ff;
    border-radius: .35rem;
    padding: .1rem .3rem;
}
@keyframes spin { to { transform: rotate(360deg) } }
.done { color: #27ae60; font-weight: 600 }
.err { color: #e74c3c }
@media (max-width: 600px) {
  .qr-section { display: none }
  .mobile-section { display: block }
}
"""


_CREDENTIAL_LOGIN_JS = """\
(function () {
    var body = document.body;
    var nonce = body ? body.getAttribute('data-nonce') : '';
    var dcApiRequestUrl = body ? body.getAttribute('data-dc-api-request-url') : '';
    var dcApiSubmitUrl = body ? body.getAttribute('data-dc-api-submit-url') : '';
    var dcApiProtocol = body ? body.getAttribute('data-dc-api-protocol') : 'openid4vp-v1-signed';
  var qrSection = document.getElementById('qr-section');
  var mobileSection = document.getElementById('mobile-section');
  var qrFallback = document.getElementById('qr-fallback');
  var status = document.getElementById('status');
    var walletSelect = document.getElementById('wallet-select');
    var platformSelect = document.getElementById('platform-select');
    var walletLink = document.getElementById('wallet-link');
    var walletHelp = document.getElementById('wallet-help');
    var userAgent = navigator.userAgent || '';
    var dcApiRequestJwt = '';
    var dcApiPrefetch = null;

    function supportsDigitalCredentials() {
        if (!window.isSecureContext || !dcApiRequestUrl || !dcApiSubmitUrl) {
            return false;
        }
        if (typeof DigitalCredential === 'undefined') {
            return false;
        }
        if (!navigator.credentials || typeof navigator.credentials.get !== 'function') {
            return false;
        }
        try {
            return !!DigitalCredential.userAgentAllowsProtocol(dcApiProtocol);
        } catch (error) {
            return false;
        }
    }

    var dcApiSupported = supportsDigitalCredentials();

  function setStatus(html) {
    if (status) {
      status.innerHTML = html;
    }
  }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function renderVerificationFailure(data) {
        var message = data && data.message ? data.message : 'Verification failed.';
        var detail = data && data.detail ? data.detail : '';
        var html = '<span class="err">' + escapeHtml(message) + '</span>';
        if (detail) {
            html += '<div class="status-detail">' + escapeHtml(detail) + '</div>';
        }
        html += '<div class="status-detail"><a href="/v1/auth/credential-login">Try again</a></div>';
        return html;
    }

  function showMobile() {
    if (qrSection) {
      qrSection.style.display = 'none';
    }
    if (mobileSection) {
      mobileSection.style.display = 'block';
    }
  }

  function showQr() {
    if (qrFallback) {
      qrFallback.style.display = 'block';
    }
  }

    function formatDcApiError(error) {
        if (!error) {
            return 'Wallet request failed.';
        }
        if (typeof error === 'string') {
            return error;
        }
        if (error.error_description) {
            return error.error_description;
        }
        if (error.detail) {
            if (typeof error.detail === 'string') {
                return error.detail;
            }
            if (error.detail.error_description) {
                return error.detail.error_description;
            }
            if (error.detail.error) {
                return error.detail.error;
            }
        }
        if (error.name === 'NotAllowedError') {
            return 'Wallet request was canceled.';
        }
        if (error.message) {
            return error.message;
        }
        return 'Wallet request failed.';
    }

    function prefetchDigitalCredentialRequest() {
        if (!dcApiSupported || !dcApiRequestUrl || dcApiRequestJwt || dcApiPrefetch) {
            return;
        }

        dcApiPrefetch = fetch(dcApiRequestUrl, {
            credentials: 'same-origin',
            headers: { Accept: 'application/oauth-authz-req+jwt' }
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('Failed to prepare wallet request.');
                }
                return response.text();
            })
            .then(function (requestJwt) {
                dcApiRequestJwt = requestJwt;
                return requestJwt;
            })
            .catch(function (error) {
                console.warn('Digital Credentials request prefetch failed', error);
            })
            .finally(function () {
                dcApiPrefetch = null;
            });
    }

    function setWalletBusy(isBusy) {
        if (!walletLink) {
            return;
        }
        if (isBusy) {
            walletLink.setAttribute('aria-disabled', 'true');
            walletLink.setAttribute('data-busy', 'true');
            walletLink.style.pointerEvents = 'none';
            walletLink.style.opacity = '0.75';
            return;
        }
        walletLink.removeAttribute('aria-disabled');
        walletLink.removeAttribute('data-busy');
        walletLink.style.pointerEvents = '';
        walletLink.style.opacity = '';
    }

    function submitDigitalCredential(credential) {
        return fetch(dcApiSubmitUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                protocol: credential && credential.protocol ? credential.protocol : dcApiProtocol,
                origin: window.location.origin,
                data: credential && credential.data ? credential.data : {}
            })
        }).then(function (response) {
            if (response.ok) {
                return response.json().catch(function () { return {}; });
            }
            return response.json()
                .catch(function () { return {}; })
                .then(function (payload) {
                    throw payload;
                });
        });
    }

    function launchDigitalCredentials() {
        if (!dcApiRequestJwt) {
            prefetchDigitalCredentialRequest();
            setStatus('<span class="err">Preparing the wallet chooser. Tap Open wallet again in a moment.</span>');
            setWalletBusy(false);
            return Promise.resolve();
        }

        return navigator.credentials.get({
            mediation: 'required',
            digital: {
                requests: [{
                    protocol: dcApiProtocol,
                    data: {
                        request: dcApiRequestJwt
                    }
                }]
            }
        })
            .then(function (credential) {
                if (!credential || !credential.data) {
                    throw new Error('Wallet returned an empty credential response.');
                }
                if (credential.data.error) {
                    throw credential.data;
                }
                setStatus('<span class="spinner"></span> Wallet response received. Finalizing sign-in&hellip;');
                return submitDigitalCredential(credential);
            })
            .catch(function (error) {
                setStatus('<span class="err">' + formatDcApiError(error) + '</span>');
            })
            .finally(function () {
                setWalletBusy(false);
            });
    }

    function detectPlatform() {
        if (/Android/i.test(userAgent)) {
            return 'android';
    }
        if (/iPhone|iPad|iPod/i.test(userAgent)) {
            return 'ios';
        }
        return 'generic';
    }

    function selectedPlatform() {
        var platform = platformSelect ? platformSelect.value : 'auto';
        return platform === 'auto' ? detectPlatform() : platform;
    }

    function syncWalletLaunch() {
        if (!walletSelect) {
            return;
        }

        var selectedOption = walletSelect.options[walletSelect.selectedIndex];
        if (!selectedOption) {
            return;
        }

        try {
            window.localStorage.setItem('marty.credential_login.wallet', walletSelect.value || '');
        } catch (storageError) {
            // Private mode or quota errors are non-fatal.
        }

        var href = selectedOption.getAttribute('data-link') || '';
        var platform = selectedPlatform();
        var label = selectedOption.textContent || 'selected wallet';
        var description = selectedOption.getAttribute('data-description') || 'Select your wallet, then tap Open wallet.';

        if (platform === 'android') {
            href = selectedOption.getAttribute('data-android-link') || href;
        } else if (platform === 'ios') {
            href = selectedOption.getAttribute('data-ios-link') || href;
        }

        if (walletLink && href) {
            walletLink.setAttribute('href', href);
            walletLink.setAttribute('aria-label', 'Open wallet with ' + label);
        }

        if (walletHelp) {
            walletHelp.textContent = dcApiSupported
                ? 'Your browser will open the system wallet chooser on this device. Use the QR code if you prefer another device.'
                : description;
    }
    }

    function restoreWalletPreference() {
        if (!walletSelect) {
            return;
        }
        var storedWallet = '';
        var storedPlatform = '';
        try {
            storedWallet = window.localStorage.getItem('marty.credential_login.wallet') || '';
            storedPlatform = window.localStorage.getItem('marty.credential_login.platform') || '';
        } catch (storageError) {
            return;
        }
        if (storedWallet) {
            for (var i = 0; i < walletSelect.options.length; i += 1) {
                if (walletSelect.options[i].value === storedWallet) {
                    walletSelect.selectedIndex = i;
                    break;
                }
            }
        }
        if (storedPlatform && platformSelect) {
            for (var j = 0; j < platformSelect.options.length; j += 1) {
                if (platformSelect.options[j].value === storedPlatform) {
                    platformSelect.selectedIndex = j;
                    break;
                }
            }
        }
    }

    function persistPlatformPreference() {
        if (!platformSelect) {
            return;
        }
        try {
            window.localStorage.setItem('marty.credential_login.platform', platformSelect.value || '');
        } catch (storageError) {
            // Non-fatal.
        }
    }

  var showMobileButton = document.querySelector('[data-action="show-mobile"]');
  if (showMobileButton) {
    showMobileButton.addEventListener('click', showMobile);
  }

  var showQrButton = document.querySelector('[data-action="show-qr"]');
  if (showQrButton) {
    showQrButton.addEventListener('click', showQr);
  }

    if (walletSelect) {
        restoreWalletPreference();
        walletSelect.addEventListener('change', syncWalletLaunch);
        syncWalletLaunch();
    }

    if (platformSelect) {
        platformSelect.addEventListener('change', function () {
            persistPlatformPreference();
            syncWalletLaunch();
        });
        syncWalletLaunch();
    }

    if (walletLink) {
        walletLink.addEventListener('click', function (event) {
            if (!dcApiSupported) {
                return;
            }
            event.preventDefault();
            if (walletLink.getAttribute('data-busy') === 'true') {
                return;
            }
            setWalletBusy(true);
            setStatus('<span class="spinner"></span> Opening your wallet chooser&hellip;');
            launchDigitalCredentials();
        });
    }

    if (dcApiSupported) {
        prefetchDigitalCredentialRequest();
    }

    if (/Android|iPhone|iPad|iPod|Mobile/i.test(userAgent)) {
        showMobile();
    }

    if (!nonce) {
        setStatus('<span class="err">Login session missing. <a href="/v1/auth/credential-login">Try again</a></span>');
        return;
    }

    var attempts = 0;
    var maxAttempts = 180;
    var timer = setInterval(function () {
        attempts += 1;
        if (attempts > maxAttempts) {
            clearInterval(timer);
            setStatus('<span class="err">Timed out. <a href="/v1/auth/credential-login">Try again</a></span>');
            return;
    }

    fetch('/v1/auth/credential-login/status?nonce=' + encodeURIComponent(nonce), {
      credentials: 'same-origin'
    })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (data.status === 'completed') {
          clearInterval(timer);
          setStatus('<span class="done">&#10003; Verified! Redirecting&hellip;</span>');
          window.location.href = data.redirect_to || '/';
        } else if (data.status === 'failed') {
          clearInterval(timer);
                    setStatus(renderVerificationFailure(data));
        } else if (data.status === 'expired') {
          clearInterval(timer);
          setStatus('<span class="err">Login session expired. <a href="/v1/auth/credential-login">Try again</a></span>');
        }
      })
      .catch(function () {
        // Keep polling through transient network hiccups.
      });
  }, 2500);
})();
"""


_CREDENTIAL_LOGIN_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in with Open Badge Credential &mdash; Marty</title>
    <link rel="stylesheet" href="/v1/auth/credential-login/assets/styles.css?v={asset_version}">
    <script src="/v1/auth/credential-login/assets/app.js?v={asset_version}" defer></script>
</head>
<body data-nonce="{nonce_attr}" data-dc-api-request-url="{dc_api_request_url_attr}" data-dc-api-submit-url="{dc_api_submit_url_attr}" data-dc-api-protocol="{dc_api_protocol_attr}">
  <div class="card">
    <!-- Icon -->
    <svg class="logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="48" height="48" rx="12" fill="#1a73e8"/>
      <path d="M14 20a10 10 0 0 1 20 0v2h2a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H12
               a2 2 0 0 1-2-2V24a2 2 0 0 1 2-2h2v-2z" fill="white" opacity=".9"/>
      <circle cx="24" cy="29" r="3" fill="#1a73e8"/>
    </svg>

    <h1>Sign in with Open Badge Credential</h1>
    <p class="subtitle">Use your wallet to present an Open Badge credential and authenticate securely &mdash; no password needed.</p>

        <div class="wallet-controls">
            <div class="wallet-picker">
                <label class="wallet-label" for="wallet-select">Select wallet app</label>
                <select class="wallet-select" id="wallet-select" name="wallet-select">
                    {wallet_option_tags}
                </select>
            </div>
            <div class="wallet-picker">
                <label class="wallet-label" for="platform-select">Platform</label>
                <select class="wallet-select" id="platform-select" name="platform-select">
                    <option value="auto" selected>Auto-detect</option>
                    <option value="android">Android</option>
                    <option value="ios">iOS</option>
                    <option value="generic">Generic</option>
                </select>
            </div>
        </div>

    <!-- Desktop: QR code -->
    <div class="qr-section" id="qr-section">
      <img
        src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=8&data={qr_encoded}"
        alt="Scan QR with Marty wallet"
      >
      <p class="qr-label">Scan with your wallet app</p>
      <button class="toggle-link" type="button" data-action="show-mobile">On this device? Open in wallet &rsaquo;</button>
    </div>

    <!-- Mobile: deep-link button -->
    <div class="mobile-section" id="mobile-section">
      <a class="open-btn" href="{oid4vp_uri_escaped}" id="wallet-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2"/>
          <path d="M8 21h8M12 17v4"/>
        </svg>
                <span>Open wallet</span>
      </a>
            <p class="mobile-help" id="wallet-help">{wallet_help_text}</p>
      <button class="toggle-link" type="button" data-action="show-qr">Show QR code instead &rsaquo;</button>
      <div>
        <div class="qr-section qr-fallback" id="qr-fallback">
          <img
            src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&margin=6&data={qr_encoded}"
            alt="Scan QR with Marty wallet" class="qr-small"
          >
        </div>
      </div>
    </div>

    <hr class="divider">
    <div class="status" id="status">
      <span class="spinner"></span> Waiting for wallet response&hellip;
    </div>
  </div>

  <!-- Legacy inline script kept inert; CSP-safe script is loaded from /assets/app.js.
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
  -->
</body>
</html>
"""


_CREDENTIAL_LOGIN_ERROR_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title} &mdash; Marty</title>
    <link rel="stylesheet" href="/v1/auth/credential-login/assets/styles.css?v={asset_version}">
</head>
<body>
    <div class="card">
        <svg class="logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="48" height="48" rx="12" fill="#f97316"/>
            <path d="M14 20a10 10 0 0 1 20 0v2h2a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H12
                             a2 2 0 0 1-2-2V24a2 2 0 0 1 2-2h2v-2z" fill="white" opacity=".95"/>
            <path d="M24 26.5l3.5 3.5M27.5 26.5L24 30" stroke="#f97316" stroke-width="2.5" stroke-linecap="round"/>
        </svg>

        <div class="status-eyebrow">Open Badge sign-in unavailable</div>
        <h1>{title}</h1>
        <p class="subtitle">{message}</p>
        {operator_details_html}
        <div class="action-group">
            {actions_html}
        </div>
    </div>
</body>
</html>
"""


@router.get("/credential-login/assets/styles.css", include_in_schema=False)
async def credential_login_styles() -> Response:
    return Response(
        content=_CREDENTIAL_LOGIN_CSS,
        media_type="text/css",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@router.get("/credential-login/assets/app.js", include_in_schema=False)
async def credential_login_script() -> Response:
    return Response(
        content=_CREDENTIAL_LOGIN_JS,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@router.get("/credential-login", response_class=HTMLResponse)
async def credential_login(request: Request) -> HTMLResponse:
    """
    Initiate an OID4VP login flow.

    Returns an HTML page with a QR code for the Marty wallet to scan.
    Polling via /credential-login/status detects completion.
    """
    if not _credential_login_policy_id:
        return _credential_login_unavailable_response(
            request,
            title="Open Badge sign-in is not configured yet",
            message=(
                "This deployment is missing the configuration required to start "
                "Open Badge passwordless sign-in. Use another sign-in method, "
                "or contact your ElevenID operator to finish setup."
            ),
            operator_details=(
                "Set CREDENTIAL_LOGIN_POLICY_ID to "
                f"{_DEFAULT_OPEN_BADGE_LOGIN_POLICY_ID} and restart the auth service."
            ),
        )
    if _redis_client is None:
        return _credential_login_unavailable_response(
            request,
            title="Open Badge sign-in is temporarily unavailable",
            message=(
                "The sign-in service is still starting or unavailable right now. "
                "Please try again in a moment, or use another sign-in method."
            ),
            operator_details="Redis/session storage is unavailable in the auth service.",
            allow_retry=True,
        )

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
        return _credential_login_unavailable_response(
            request,
            title="Open Badge sign-in is temporarily unavailable",
            message=(
                "We could not start the wallet sign-in flow right now. Please "
                "try again in a moment, or use another sign-in method."
            ),
            operator_details="The auth service could not reach the flow service to start verification.",
            allow_retry=True,
        )

    instance_id: str = flow_data.get("instance_id", "")
    # request_uri is the full openid4vp://authorize?... URI
    oid4vp_uri: str = flow_data.get("request_uri", flow_data.get("qr_code_data", ""))

    # Persist pending state with MIP Flow instance linkage
    await _redis_client.setex(
        f"{_PENDING_KEY}{nonce}",
        _PENDING_TTL,
        json.dumps({"nonce": nonce, "flow_instance_id": instance_id, "status": "pending", "revocation_checked": False}),
    )

    qr_encoded = quote(oid4vp_uri, safe="")
    html_content = _render_credential_login_page(
        nonce=nonce,
        flow_instance_id=instance_id,
        qr_encoded=qr_encoded,
        oid4vp_uri=oid4vp_uri,
        request_uri=flow_data.get("request_uri", ""),
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
                "revocation_checked": data.get("revocation_checked", False),
                "revocation_status": data.get("revocation_status", "unknown"),
            }
        if status == "failed":
            return _coerce_credential_login_failure_payload(data)
        return {
            "status": status,
            "redirect_to": data.get("redirect_to", "/"),
            "revocation_checked": data.get("revocation_checked", False),
            "revocation_status": data.get("revocation_status", "unknown"),
        }

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
            url=_credential_login_failure_redirect_url(data),
            status_code=302,
        )

    session_id: str = data.get("session_id", "")
    if not session_id:
        return RedirectResponse(
            url=f"{_ui_base_url}/?auth_error=Session+creation+failed", status_code=302
        )

    # Consume the completion key so it can't be replayed
    await _redis_client.delete(f"{_COMPLETE_KEY}{nonce}")

    redirect = RedirectResponse(
        url=_build_ui_redirect_url("/", _ui_base_url),
        status_code=302,
    )
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


async def _mark_credential_login_failed(nonce: str, reason: str) -> None:
    if _redis_client is None:
        return
    await _redis_client.setex(
        f"{_COMPLETE_KEY}{nonce}",
        _COMPLETE_TTL,
        json.dumps(_credential_login_failure_payload(reason)),
    )
    await _redis_client.delete(f"{_PENDING_KEY}{nonce}")


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
        logger.info(
            "Credential verification denied: decision=%s result=%s reason=%s",
            payload.decision,
            payload.result,
            payload.decision_reason or "<none>",
        )
        await _mark_credential_login_failed(
            nonce,
            payload.decision_reason or "Credential verification failed",
        )
        return {"ok": True, "status": "denied"}

    # Extract identity claims from the VP
    claims = payload.verified_claims
    email: str = claims.get("email", "")
    given_name: str | None = claims.get("given_name")
    family_name: str | None = claims.get("family_name")
    role: str = claims.get("role", "applicant")
    preferred_username = claims.get("preferred_username") if isinstance(claims.get("preferred_username"), str) else email
    if not email:
        logger.warning(
            "credential-verified: missing email claim for flow=%s nonce=%s",
            payload.flow_instance_id,
            f"{nonce[:8]}...",
        )
        await _mark_credential_login_failed(nonce, "Credential missing email claim")
        return {"ok": True, "status": "denied"}

    keycloak_user = None
    kc_tokens: dict[str, str] | None = None

    if _kc_admin_adapter is not None:
        try:
            kc_user_id = None
            get_existing_verified_user_id = getattr(_kc_admin_adapter, "get_existing_verified_user_id", None)
            if callable(get_existing_verified_user_id):
                kc_user_id = await get_existing_verified_user_id(email=email, username=preferred_username)
            elif _credential_login_create_users:
                kc_user_id = await _kc_admin_adapter.get_or_create_user(
                    email=email,
                    username=preferred_username,
                    given_name=given_name,
                    family_name=family_name,
                    role=role,
                )
            # Keep credential-login session parity with OIDC login:
            # when Keycloak admin integration is enabled and user creation is
            # disabled, require an existing Keycloak user and deny fallback to
            # synthetic claim-only identities.
            require_existing_kc_user = _credential_login_require_existing_keycloak_user or not _credential_login_create_users
            if not kc_user_id and require_existing_kc_user:
                await _mark_credential_login_failed(nonce, "keycloak_user_not_found")
                return {"ok": True, "status": "denied"}
            if kc_user_id:
                kc_tokens = await _kc_admin_adapter.exchange_token_for_user(kc_user_id)
                if kc_tokens and (kc_tokens.get("id_token") or kc_tokens.get("access_token")):
                    try:
                        keycloak_user = build_oidc_user_info(
                            id_token=kc_tokens.get("id_token"),
                            access_token=kc_tokens.get("access_token"),
                        )
                    except ValueError as kc_claim_exc:
                        logger.warning(
                            "KC token claim parsing failed during credential login for %s: %s",
                            email,
                            kc_claim_exc,
                        )
                admin_keycloak_user = None
                get_user_info = getattr(_kc_admin_adapter, "get_user_info", None)
                if callable(get_user_info):
                    admin_keycloak_user = await get_user_info(kc_user_id)
                if merge_oidc_user_info is not None:
                    keycloak_user = merge_oidc_user_info(keycloak_user, admin_keycloak_user)
                elif keycloak_user is None:
                    keycloak_user = admin_keycloak_user
        except Exception as kc_exc:
            logger.warning("KC enrichment failed during credential login for %s: %s", email, kc_exc)
            require_existing_kc_user = _credential_login_require_existing_keycloak_user or not _credential_login_create_users
            if require_existing_kc_user:
                await _mark_credential_login_failed(nonce, "keycloak_user_not_eligible")
                return {"ok": True, "status": "denied"}
    elif _credential_login_require_existing_keycloak_user:
        await _mark_credential_login_failed(nonce, "keycloak_admin_unavailable")
        return {"ok": True, "status": "denied"}

    user = await build_credential_login_user(
        claims,
        _user_provisioning,
        keycloak_user=keycloak_user,
    )
    user = apply_credential_login_defaults(user)
    if _applicant_profile_provisioner is not None:
        try:
            applicant_id = await _applicant_profile_provisioner(user)
            if applicant_id:
                user.applicant_id = applicant_id
        except Exception as exc:
            logger.warning(
                "Applicant profile provisioning failed during credential login for %s: %s",
                email,
                exc,
            )

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    session = Session.create(
        user=user,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if kc_tokens:
        session.id_token = kc_tokens.get("id_token")
        session.refresh_token = kc_tokens.get("refresh_token")
        logger.debug("KC tokens obtained for %s", email)

    await _session_repository.save(session)

    logger.info(
        f"Credential login succeeded: user={email} session={session.session_id[:8]}..."
    )

    # Signal the polling endpoint with revocation status
    revocation_checked = bool(payload.verified_claims.get("revocation_checked"))
    revocation_status = str(payload.verified_claims.get("revocation_status", "unknown"))
    await _redis_client.setex(
        f"{_COMPLETE_KEY}{nonce}",
        _COMPLETE_TTL,
        json.dumps({
            "status": "completed",
            "session_id": session.session_id,
            "revocation_checked": revocation_checked,
            "revocation_status": revocation_status,
        }),
    )
    # Clean up pending key
    await _redis_client.delete(f"{_PENDING_KEY}{nonce}")

    return {"ok": True, "status": "completed", "session_id": session.session_id}
