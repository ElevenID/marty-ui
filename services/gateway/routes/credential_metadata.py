"""Public credential type metadata for wallet display/resolution."""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

credential_metadata_router = APIRouter(tags=["Credential Metadata"])

MARTY_BADGE_SLUG = "marty-verified-member-badge"
MARTY_BADGE_NAME = "Marty Verified Member Badge"
MARTY_BADGE_DESCRIPTION = (
    "Verified membership credential issued by Marty Identity Platform for secure passwordless sign-in."
)
MARTY_BADGE_BACKGROUND = "#3B1C8F"
MARTY_BADGE_TEXT = "#FFFFFF"


def _public_base_url(request: Request) -> str:
    configured = (
        os.environ.get("PUBLIC_API_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_BASE_URL")
    )
    if configured:
        return configured.rstrip("/")
    return str(request.base_url).rstrip("/")


def _badge_url(request: Request, suffix: str = "") -> str:
    base = _public_base_url(request)
    return f"{base}/credentials/{MARTY_BADGE_SLUG}{suffix}"


def _badge_display(request: Request) -> dict[str, Any]:
    logo = {
        "uri": _badge_url(request, "/image.svg"),
        "alt_text": MARTY_BADGE_NAME,
    }
    return {
        "lang": "en-US",
        "locale": "en-US",
        "name": MARTY_BADGE_NAME,
        "description": MARTY_BADGE_DESCRIPTION,
        "background_color": MARTY_BADGE_BACKGROUND,
        "text_color": MARTY_BADGE_TEXT,
        "logo": logo,
        "rendering": {
            "simple": {
                "logo": logo,
                "background_color": MARTY_BADGE_BACKGROUND,
                "text_color": MARTY_BADGE_TEXT,
            }
        },
    }


@credential_metadata_router.get(
    f"/credentials/{MARTY_BADGE_SLUG}",
    summary="Marty Verified Member Badge type metadata",
    response_class=JSONResponse,
)
async def get_marty_verified_member_badge_metadata(request: Request) -> JSONResponse:
    """Return SD-JWT VC type metadata for the Marty membership badge."""
    metadata = {
        "vct": _badge_url(request),
        "name": MARTY_BADGE_NAME,
        "description": MARTY_BADGE_DESCRIPTION,
        "display": [_badge_display(request)],
        "claims": [
            {
                "path": ["email"],
                "display": [{"lang": "en-US", "name": "Email Address"}],
                "sd": "always",
            },
            {
                "path": ["member_id"],
                "display": [{"lang": "en-US", "name": "Member ID"}],
                "sd": "always",
            },
            {
                "path": ["organization_name"],
                "display": [{"lang": "en-US", "name": "Organization"}],
                "sd": "allowed",
            },
            {
                "path": ["role"],
                "display": [{"lang": "en-US", "name": "Role"}],
                "sd": "always",
            },
            {
                "path": ["achievement_name"],
                "display": [{"lang": "en-US", "name": "Badge Name"}],
                "sd": "never",
            },
        ],
    }
    return JSONResponse(
        content=metadata,
        headers={"Cache-Control": "public, max-age=300"},
    )


@credential_metadata_router.get(
    f"/credentials/{MARTY_BADGE_SLUG}/image.svg",
    summary="Marty Verified Member Badge image",
)
async def get_marty_verified_member_badge_image() -> Response:
    """Return a compact SVG badge mark for wallet display metadata."""
    svg = """<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"512\" height=\"512\" viewBox=\"0 0 512 512\" role=\"img\" aria-label=\"Marty Verified Member Badge\">
  <defs>
    <linearGradient id=\"g\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\">
      <stop offset=\"0%\" stop-color=\"#6A3CFF\"/>
      <stop offset=\"100%\" stop-color=\"#241057\"/>
    </linearGradient>
  </defs>
  <rect width=\"512\" height=\"512\" rx=\"96\" fill=\"url(#g)\"/>
  <path d=\"M256 76l142 54v112c0 87-58 153-142 194-84-41-142-107-142-194V130l142-54z\" fill=\"#fff\" opacity=\".14\"/>
  <path d=\"M221 282l-47-47-32 32 79 79 158-158-32-32-126 126z\" fill=\"#fff\"/>
  <text x=\"256\" y=\"410\" text-anchor=\"middle\" font-family=\"Inter, Segoe UI, Arial, sans-serif\" font-size=\"44\" font-weight=\"800\" fill=\"#fff\">MARTY</text>
  <text x=\"256\" y=\"452\" text-anchor=\"middle\" font-family=\"Inter, Segoe UI, Arial, sans-serif\" font-size=\"26\" font-weight=\"700\" fill=\"#E9E1FF\">VERIFIED MEMBER</text>
</svg>"""
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )
