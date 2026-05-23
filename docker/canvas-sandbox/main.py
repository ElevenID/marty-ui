"""Canvas Credentials Test Sandbox — simulates a Canvas LMS LTI 1.3 platform for local dev."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CANVAS_SANDBOX_HOST = os.environ.get("CANVAS_SANDBOX_HOST", "canvas-sandbox")
CANVAS_SANDBOX_PORT = int(os.environ.get("CANVAS_SANDBOX_PORT", "8017"))
CANVAS_SANDBOX_SCHEME = os.environ.get("CANVAS_SANDBOX_SCHEME", "http")
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://gateway:8000")
CANVAS_CREDENTIALS_PUBLIC_BASE_URL = os.environ.get("CANVAS_CREDENTIALS_PUBLIC_BASE_URL", "").strip()
CANVAS_CREDENTIALS_SHARED_SECRET = os.environ.get("CANVAS_CREDENTIALS_SHARED_SECRET", "")
CANVAS_CREDENTIALS_API_TOKEN = os.environ.get("CANVAS_CREDENTIALS_API_TOKEN", "")
CANVAS_CREDENTIALS_ISSUER_ID = os.environ.get(
    "CANVAS_CREDENTIALS_ISSUER_ID",
    "canvas-credentials-test-sandbox-issuer",
)
CANVAS_CREDENTIALS_BADGE_NAME = os.environ.get(
    "CANVAS_CREDENTIALS_BADGE_NAME",
    "Interoperable Credentials Foundations Badge",
)

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

_MIRRORED_CREDENTIALS: dict[str, dict] = {}
_STATUS_SYNC_EVENTS: list[dict] = []

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


def _payload_hash(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _authorize_canvas_credentials_api(authorization: str | None) -> JSONResponse | None:
    """Require a bearer token only when the sandbox was configured with one."""

    if not CANVAS_CREDENTIALS_API_TOKEN:
        return None
    expected = f"Bearer {CANVAS_CREDENTIALS_API_TOKEN}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        return JSONResponse(status_code=401, content={"error": "invalid_canvas_credentials_token"})
    return None


def _public_canvas_credentials_base_url() -> str:
    if CANVAS_CREDENTIALS_PUBLIC_BASE_URL:
        return CANVAS_CREDENTIALS_PUBLIC_BASE_URL.rstrip("/")
    public_host = os.environ.get("CANVAS_SANDBOX_PUBLIC_HOST", "").strip()
    if public_host:
        scheme = CANVAS_SANDBOX_SCHEME.strip() or "https"
        return f"{scheme}://{public_host}".rstrip("/")
    host = CANVAS_SANDBOX_HOST.strip()
    scheme = CANVAS_SANDBOX_SCHEME.strip() or "https"
    if not host:
        return PUBLIC_BASE_URL.rstrip("/")
    if ":" in host:
        return f"{scheme}://{host}".rstrip("/")
    if host in {"localhost", "127.0.0.1", "canvas-sandbox"}:
        return f"{scheme}://{host}:{CANVAS_SANDBOX_PORT}".rstrip("/")
    return f"{scheme}://{host}".rstrip("/")


def _credential_display_url(external_credential_id: str) -> str:
    return f"{_public_canvas_credentials_base_url()}/credentials/{quote(external_credential_id)}"


def _employer_verification_url(record: dict) -> str:
    query = {
        "external_credential_id": record.get("id") or "",
        "canvas_account_id": record.get("canvas_account_id") or "",
        "organization_id": record.get("organization_id") or "",
    }
    return f"{ISSUER_BASE_URL.rstrip()}/verify/canvas-credentials?{urlencode({k: v for k, v in query.items() if v})}"


def _html(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


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
    application_id: str = ""
    organization_id: str = ""
    credential_template_id: str = ""
    evidence_type: str = "canvas.course_completion"
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
    """POST signed Canvas evidence to the issuance service (like Canvas would)."""
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

    target_url = f"{ISSUER_BASE_URL}/v1/integrations/canvas/evidence-events"
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
# Canvas Credentials mirror receiver (beta-safe external API stand-in)
# ---------------------------------------------------------------------------
@app.post("/api/credentials/mirror/publish")
async def publish_canvas_credentials_mirror(
    request: Request,
    authorization: str | None = Header(None),
):
    auth_error = _authorize_canvas_credentials_api(authorization)
    if auth_error is not None:
        return auth_error

    payload = await request.json()
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "payload_must_be_object"})

    credential = payload.get("credential") if isinstance(payload.get("credential"), dict) else {}
    source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    credential_id = str(credential.get("id") or "").strip()
    delivery_record_id = str(source.get("delivery_record_id") or "").strip()
    if not credential_id:
        return JSONResponse(status_code=422, content={"error": "credential.id is required"})

    external_credential_id = f"canvas-sandbox-{credential_id}"
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "id": external_credential_id,
        "issuer_id": payload.get("issuer_id") or CANVAS_CREDENTIALS_ISSUER_ID,
        "canonical_credential_id": credential_id,
        "delivery_record_id": delivery_record_id or None,
        "organization_id": payload.get("organization_id"),
        "canvas_account_id": payload.get("canvas_account_id"),
        "canvas_platform_id": payload.get("canvas_platform_id"),
        "canvas_program_binding_id": payload.get("canvas_program_binding_id"),
        "credential_hash": credential.get("hash"),
        "issuer_did": credential.get("issuer_did"),
        "subject_did": (payload.get("recipient") or {}).get("subject_did")
        if isinstance(payload.get("recipient"), dict)
        else None,
        "status": "active",
        "payload_hash": _payload_hash(payload),
        "created_at": now,
        "updated_at": now,
    }
    record["credential_url"] = _credential_display_url(external_credential_id)
    record["employer_verification_url"] = _employer_verification_url(record)
    _MIRRORED_CREDENTIALS[external_credential_id] = record

    return JSONResponse(
        headers={"x-request-id": secrets.token_hex(12)},
        content={
            "id": external_credential_id,
            "credential_id": external_credential_id,
            "issuer_id": payload.get("issuer_id") or CANVAS_CREDENTIALS_ISSUER_ID,
            "status": "active",
            "credential_url": record["credential_url"],
            "employer_verification_url": record["employer_verification_url"],
            "credential": {
                "id": external_credential_id,
                "canonical_id": credential_id,
                "issuer_did": credential.get("issuer_did"),
            },
        },
    )


@app.post("/api/credentials/mirror/status")
async def sync_canvas_credentials_status(
    request: Request,
    authorization: str | None = Header(None),
):
    auth_error = _authorize_canvas_credentials_api(authorization)
    if auth_error is not None:
        return auth_error

    payload = await request.json()
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "payload_must_be_object"})

    credential = payload.get("credential") if isinstance(payload.get("credential"), dict) else {}
    external_id = str(credential.get("external_credential_id") or credential.get("id") or "").strip()
    now = datetime.now(timezone.utc).isoformat()
    event = {
        "id": f"status-sync-{secrets.token_hex(8)}",
        "external_credential_id": external_id or None,
        "lifecycle_action": payload.get("lifecycle_action"),
        "status": credential.get("status"),
        "reason": credential.get("reason"),
        "payload_hash": _payload_hash(payload),
        "created_at": now,
    }
    _STATUS_SYNC_EVENTS.append(event)
    if external_id and external_id in _MIRRORED_CREDENTIALS:
        _MIRRORED_CREDENTIALS[external_id]["status"] = str(credential.get("status") or "").lower() or "updated"
        _MIRRORED_CREDENTIALS[external_id]["updated_at"] = now

    return JSONResponse(
        headers={"x-request-id": secrets.token_hex(12)},
        content={
            "status": "synced",
            "event_id": event["id"],
            "external_credential_id": external_id or None,
        },
    )


@app.get("/api/credentials/mirror/{external_credential_id}")
async def get_canvas_credentials_mirror(
    external_credential_id: str,
    authorization: str | None = Header(None),
):
    auth_error = _authorize_canvas_credentials_api(authorization)
    if auth_error is not None:
        return auth_error

    record = _MIRRORED_CREDENTIALS.get(external_credential_id)
    if record is None:
        return JSONResponse(status_code=404, content={"error": "credential_not_found"})
    return JSONResponse(content=record)


@app.get("/credentials/{external_credential_id}")
async def display_canvas_credentials_mirror(external_credential_id: str):
    """Public demo display for a mirrored Canvas Credentials badge."""

    record = _MIRRORED_CREDENTIALS.get(external_credential_id)
    if record is None:
        return HTMLResponse(
            status_code=404,
            content=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Canvas Credentials Mirror</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 0; background: #f6f8fb; color: #1f2937; }}
main {{ max-width: 760px; margin: 72px auto; background: white; border: 1px solid #d9dee8; border-radius: 12px; padding: 32px; }}
h1 {{ margin-top: 0; }}
</style>
</head>
<body><main><h1>Credential not found</h1><p>No mirrored Canvas credential exists for <code>{_html(external_credential_id)}</code>.</p></main></body>
</html>""",
        )

    employer_url = record.get("employer_verification_url") or _employer_verification_url(record)
    status = str(record.get("status") or "unknown").upper()
    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_html(CANVAS_CREDENTIALS_BADGE_NAME)} - Canvas Credentials</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 0; background: #f4f7fb; color: #172033; }}
.bar {{ background: #1f76d2; color: white; padding: 18px 28px; font-size: 20px; font-weight: 700; }}
main {{ max-width: 920px; margin: 40px auto; padding: 0 20px; }}
.panel {{ background: white; border: 1px solid #d8e0ec; border-radius: 12px; padding: 28px; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06); }}
.badge {{ width: 92px; height: 92px; border-radius: 50%; background: #e8f1ff; display: grid; place-items: center; color: #1f76d2; font-size: 42px; font-weight: 800; }}
.head {{ display: flex; gap: 20px; align-items: center; }}
.status {{ display: inline-block; margin-top: 10px; padding: 6px 10px; border-radius: 999px; background: #e9f7ef; color: #166534; font-size: 13px; font-weight: 700; }}
.grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; margin-top: 28px; }}
.label {{ color: #64748b; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
.value {{ margin-top: 4px; overflow-wrap: anywhere; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
.actions {{ margin-top: 30px; display: flex; gap: 12px; flex-wrap: wrap; }}
a.button {{ background: #1f76d2; color: white; padding: 12px 16px; border-radius: 6px; text-decoration: none; font-weight: 700; }}
a.secondary {{ color: #1f76d2; padding: 12px 0; font-weight: 700; }}
@media (max-width: 720px) {{ .head {{ align-items: flex-start; flex-direction: column; }} .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="bar">Canvas Credentials</div>
<main>
  <section class="panel">
    <div class="head">
      <div class="badge">IC</div>
      <div>
        <h1>{_html(CANVAS_CREDENTIALS_BADGE_NAME)}</h1>
        <p>This badge is displayed in Canvas Credentials and backed by an external ElevenID issuance record.</p>
        <span class="status">{_html(status)}</span>
      </div>
    </div>
    <div class="grid">
      <div><div class="label">Canvas Credential ID</div><div class="value mono">{_html(record.get("id"))}</div></div>
      <div><div class="label">Canonical Credential ID</div><div class="value mono">{_html(record.get("canonical_credential_id"))}</div></div>
      <div><div class="label">Issuer DID</div><div class="value mono">{_html(record.get("issuer_did"))}</div></div>
      <div><div class="label">Canvas Account</div><div class="value mono">{_html(record.get("canvas_account_id"))}</div></div>
      <div><div class="label">Subject DID</div><div class="value mono">{_html(record.get("subject_did"))}</div></div>
      <div><div class="label">Mirrored</div><div class="value">{_html(record.get("created_at"))}</div></div>
    </div>
    <div class="actions">
      <a class="button" href="{_html(employer_url)}">Verify with Employer View</a>
      <a class="secondary" href="{_html(ISSUER_BASE_URL.rstrip())}/credentials/canvas-interoperability-foundations-badge">Open Badge Metadata</a>
    </div>
  </section>
</main>
</body>
</html>"""
    return HTMLResponse(content=html_body)


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
                "mirror_publish": "/api/credentials/mirror/publish",
                "mirror_status": "/api/credentials/mirror/status",
                "mirror_display": "/credentials/{external_credential_id}",
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
