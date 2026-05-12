"""Canvas Credentials Test Sandbox — simulates a Canvas LMS LTI 1.3 platform for local dev."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CANVAS_SANDBOX_HOST = os.environ.get("CANVAS_SANDBOX_HOST", "canvas-sandbox")
CANVAS_SANDBOX_PORT = int(os.environ.get("CANVAS_SANDBOX_PORT", "8017"))
CANVAS_SANDBOX_SCHEME = os.environ.get("CANVAS_SANDBOX_SCHEME", "http")
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://gateway:8000")
CANVAS_CREDENTIALS_SHARED_SECRET = os.environ.get("CANVAS_CREDENTIALS_SHARED_SECRET", "")

PUBLIC_BASE_URL = f"{CANVAS_SANDBOX_SCHEME}://{CANVAS_SANDBOX_HOST}:{CANVAS_SANDBOX_PORT}"
ISSUER = PUBLIC_BASE_URL
AUTHORIZATION_ENDPOINT = f"{PUBLIC_BASE_URL}/login/oauth2/auth"
TOKEN_ENDPOINT = f"{PUBLIC_BASE_URL}/login/oauth2/token"
JWKS_URI = f"{PUBLIC_BASE_URL}/api/lti/security/jwks"
REGISTRATION_ENDPOINT = f"{PUBLIC_BASE_URL}/api/lti/registrations"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Key generation (Ed25519 — same as Canvas production)
# ---------------------------------------------------------------------------
_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_KID = f"canvas-sandbox-{secrets.token_hex(4)}"

_raw_public = _PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_JWK_X = _b64url_encode(_raw_public)

_JWKS = {
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": _KID,
            "alg": "EdDSA",
            "use": "sig",
            "x": _JWK_X,
        }
    ]
}

_OIDC_CONFIGURATION = {
    "issuer": ISSUER,
    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "jwks_uri": JWKS_URI,
    "registration_endpoint": REGISTRATION_ENDPOINT,
    "scopes_supported": ["openid"],
    "response_types_supported": ["id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["EdDSA"],
    "claims_supported": [
        "iss", "sub", "aud", "exp", "iat", "nonce",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
        "https://purl.imsglobal.org/spec/lti/claim/context",
        "https://purl.imsglobal.org/spec/lti/claim/roles",
        "https://purl.imsglobal.org/spec/lti/claim/message_type",
        "https://purl.imsglobal.org/spec/lti/claim/version",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri",
    ],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sign_jwt(claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", "kid": _KID}
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = _PRIVATE_KEY.sign(signing_input)
    encoded_signature = _b64url_encode(signature)
    return f"{encoded_header}.{encoded_claims}.{encoded_signature}"


def _sign_canvas_payload(raw_body: bytes, timestamp: str) -> str:
    digest = hmac.new(
        CANVAS_CREDENTIALS_SHARED_SECRET.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + raw_body,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Canvas Credentials Test Sandbox",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
)


@app.on_event("startup")
async def _startup():
    print(f"[canvas-sandbox] issuer={ISSUER}")
    print(f"[canvas-sandbox] kid={_KID}")
    print(f"[canvas-sandbox] jwks_keys={len(_JWKS['keys'])}")


# ---------------------------------------------------------------------------
# OpenID Connect Discovery
# ---------------------------------------------------------------------------
@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    return JSONResponse(content=_OIDC_CONFIGURATION)


@app.get("/api/lti/security/jwks")
async def jwks():
    return JSONResponse(content=_JWKS)


# ---------------------------------------------------------------------------
# OIDC Authorization (LTI 1.3 login → launch redirect)
# ---------------------------------------------------------------------------
_LTI_AUTH_FORM_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Canvas Sandbox — LTI Launch</title>
</head>
<body onload="document.forms[0].submit()">
<p>Redirecting to your tool for LTI launch verification &hellip;</p>
<form method="post" action="{redirect_uri}">
<input type="hidden" name="id_token" value="{id_token}">
<input type="hidden" name="state" value="{state}">
<noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>
"""


@app.get("/login/oauth2/auth")
async def oidc_auth(
    scope: str = Query(...),
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    login_hint: str = Query(...),
    state: str = Query(...),
    nonce: str = Query(...),
    lti_message_hint: str | None = Query(None),
    prompt: str | None = Query(None),
    response_mode: str | None = Query(None),
):
    """Simulate Canvas OIDC authorization endpoint.

    Receives the LTI 1.3 login request, generates a signed id_token,
    and returns an HTML form that auto-submits to the tool's launch endpoint.
    """
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": f"canvas-user-{secrets.token_hex(4)}",
        "aud": [client_id],
        "exp": now + 3600,
        "iat": now,
        "nonce": nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "test-deployment-sandbox",
        "https://purl.imsglobal.org/spec/lti/claim/context": {
            "id": "course-sandbox-101",
            "label": "SANDBOX101",
            "title": "Canvas Sandbox Course",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": ["Learner", "Instructor"],
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": redirect_uri,
    }
    if lti_message_hint:
        claims["https://purl.imsglobal.org/spec/lti/claim/lti_message_hint"] = lti_message_hint

    id_token = _sign_jwt(claims)
    html = _LTI_AUTH_FORM_HTML.format(
        redirect_uri=redirect_uri,
        id_token=id_token,
        state=state,
    )
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Credential webhook sender (optional — simulate Canvas pushing events)
# ---------------------------------------------------------------------------
class CanvasCredentialEvent(BaseModel):
    canvas_event_id: str
    organization_id: str = ""
    credential_template_id: str = ""
    canvas_account_id: str = ""
    canvas_course_id: str = "course-sandbox-101"
    canvas_course_name: str = "Canvas Sandbox Course"
    canvas_enrollment_id: str = "enrollment-sandbox-202"
    canvas_user_id: str = "user-sandbox-303"
    learner_email: str = "student@sandbox.example.edu"
    learner_given_name: str = "Sandbox"
    learner_family_name: str = "Student"
    achievement_name: str = "Canvas Sandbox Course Completion"
    achievement_description: str = "Completed the sandbox course module."
    completion_at: str = ""


@app.post("/api/lti/credentials/webhook")
async def send_credential_event(event: CanvasCredentialEvent, request: Request):
    """POST a signed credential event to the issuance service (like Canvas would)."""
    import httpx

    if not CANVAS_CREDENTIALS_SHARED_SECRET:
        return JSONResponse(
            status_code=409,
            content={"error": "CANVAS_CREDENTIALS_SHARED_SECRET not configured in sandbox"},
        )

    if not event.completion_at:
        event.completion_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = event.model_dump()
    raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = _sign_canvas_payload(raw_body, timestamp)

    target_url = f"{ISSUER_BASE_URL}/v1/integrations/canvas/credential-events"
    headers = {
        "Content-Type": "application/json",
        "X-Canvas-Timestamp": timestamp,
        "X-Canvas-Signature-256": signature,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(target_url, content=raw_body, headers=headers)
            return JSONResponse(
                status_code=resp.status_code,
                content={
                    "sandbox_status": "sent",
                    "issuance_status": resp.status_code,
                    "issuance_response": resp.json() if resp.status_code < 500 else None,
                },
            )
        except httpx.RequestError as exc:
            return JSONResponse(
                status_code=502,
                content={"error": f"Failed to reach issuance service: {exc}"},
            )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return PlainTextResponse("ok")


@app.get("/")
async def root():
    return JSONResponse(
        content={
            "service": "canvas-credentials-test-sandbox",
            "issuer": ISSUER,
            "kid": _KID,
            "endpoints": {
                "openid_configuration": "/.well-known/openid-configuration",
                "jwks": "/api/lti/security/jwks",
                "authorization": "/login/oauth2/auth",
                "credential_webhook": "/api/lti/credentials/webhook",
            },
            "usage": {
                "connector_config": {
                    "canvas_base_url": PUBLIC_BASE_URL,
                    "lti_client_id": "any-client-id",
                    "lti_deployment_id": "test-deployment-sandbox",
                },
                "env_vars_needed": [
                    "CANVAS_ALLOW_PRIVATE_BASE_URLS=true",
                    "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS=true",
                ],
            },
        }
    )
