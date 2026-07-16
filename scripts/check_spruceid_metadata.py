#!/usr/bin/env python3
"""Fail-closed probe for SpruceKit OID4VCI issuer metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class MetadataError(ValueError):
    pass


MEMBER_CONFIGURATION_ID = "MemberCredential#spruce-sd-jwt"
MEMBER_VCT_PATH = "/credentials/marty-verified-member-badge"
EXPECTED_ISSUER_DISPLAY_NAME = "ElevenID LLC"
EXPECTED_BADGE_NAME = "Marty Verified Member Badge"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MetadataError(message)


def validate_spruce_metadata(
    metadata: dict[str, Any],
    *,
    expected_issuer: str,
    expected_issuer_display_name: str = EXPECTED_ISSUER_DISPLAY_NAME,
    expected_member_vct: str,
) -> dict[str, Any]:
    _require(metadata.get("credential_issuer") == expected_issuer, "Spruce credential_issuer mismatch")
    displays = metadata.get("display") or []
    issuer_display_names = [
        str(item.get("name") or "").strip()
        for item in displays
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    ]
    _require(expected_issuer_display_name in issuer_display_names, "Spruce issuer display name mismatch")
    configs = metadata.get("credential_configurations_supported")
    _require(isinstance(configs, dict) and bool(configs), "credential_configurations_supported is empty or malformed")
    _require(MEMBER_CONFIGURATION_ID in configs, "MemberCredential Spruce configuration is missing")

    legacy_vcts: list[str] = []
    malformed: list[str] = []
    for config_id, config in configs.items():
        if not isinstance(config, dict):
            malformed.append(config_id)
            continue
        config_format = config.get("format")
        if config_format == "spruce-vc+sd-jwt":
            if not config_id.endswith("#spruce-sd-jwt"):
                malformed.append(config_id)
            vct = str(config.get("vct") or "")
            parsed = urlparse(vct)
            if parsed.scheme != "https" or not parsed.netloc:
                malformed.append(config_id)
            if parsed.hostname == "marty.example":
                legacy_vcts.append(vct)
        elif config_format == "mso_mdoc":
            doctype = str(config.get("doctype") or "").strip()
            if not doctype or config_id != f"{doctype}#mdoc":
                malformed.append(config_id)
        else:
            malformed.append(config_id)
        config_displays = config.get("display") or []
        if not any(str(item.get("name") or "").strip() for item in config_displays if isinstance(item, dict)):
            malformed.append(config_id)
    _require(not legacy_vcts, f"Spruce metadata exposes legacy VCTs: {sorted(set(legacy_vcts))}")
    _require(not malformed, f"Malformed Spruce credential configurations: {sorted(set(malformed))}")
    member_config = configs[MEMBER_CONFIGURATION_ID]
    _require(member_config.get("format") == "spruce-vc+sd-jwt", "MemberCredential format mismatch")
    _require(member_config.get("vct") == expected_member_vct, "MemberCredential VCT mismatch")
    return {
        "credential_issuer": expected_issuer,
        "issuer_display_name": expected_issuer_display_name,
        "configuration_count": len(configs),
        "member_configuration": MEMBER_CONFIGURATION_ID,
        "member_vct": expected_member_vct,
    }


def validate_member_vct_metadata(
    metadata: dict[str, Any],
    *,
    expected_vct: str,
    expected_badge_name: str = EXPECTED_BADGE_NAME,
) -> dict[str, str]:
    _require(metadata.get("vct") == expected_vct, "MemberCredential public VCT mismatch")
    _require(metadata.get("name") == expected_badge_name, "MemberCredential badge display name mismatch")
    displays = metadata.get("display") or []
    display_names = {
        str(item.get("name") or "").strip()
        for item in displays
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    }
    _require(expected_badge_name in display_names, "MemberCredential VCT display is missing the badge name")
    return {"member_badge_name": expected_badge_name}


def _fetch_json(url: str, *, timeout: float) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Marty-MIP-Conformance/0.3.1",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
            content_type = response.headers.get("content-type", "")
            payload = response.read()
    except HTTPError as exc:
        raise MetadataError(f"{url} returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise MetadataError(f"{url} request failed: {exc.reason}") from exc

    _require(status == 200, f"{url} returned HTTP {status}")
    _require("application/json" in content_type, f"{url} is not JSON")
    try:
        body = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MetadataError(f"{url} contains invalid JSON") from exc
    _require(isinstance(body, dict), f"{url} must contain a JSON object")
    return body


def probe(base: str, org_id: str, *, timeout: float = 20.0) -> dict[str, Any]:
    base = base.rstrip("/")
    parsed_base = urlparse(base)
    _require(parsed_base.scheme == "https" and bool(parsed_base.netloc), "Beta origin must be an absolute HTTPS URL")
    expected_issuer = f"{base}/org/{org_id}/spruce"
    expected_member_vct = f"{base}{MEMBER_VCT_PATH}"
    paths = {
        "canonical": f"/.well-known/openid-credential-issuer/org/{org_id}/spruce",
        "appended": f"/org/{org_id}/spruce/.well-known/openid-credential-issuer",
        "member_vct": MEMBER_VCT_PATH,
    }
    responses: dict[str, dict[str, Any]] = {}
    for name in ("canonical", "appended"):
        path = paths[name]
        responses[name] = _fetch_json(f"{base}{path}", timeout=timeout)
    _require(responses["canonical"] == responses["appended"], "Canonical and appended Spruce metadata differ")
    summary = validate_spruce_metadata(
        responses["canonical"],
        expected_issuer=expected_issuer,
        expected_member_vct=expected_member_vct,
    )
    vct_summary = validate_member_vct_metadata(
        _fetch_json(expected_member_vct, timeout=timeout),
        expected_vct=expected_member_vct,
    )
    return {"base": base, "organization_id": org_id, "paths": paths, **summary, **vct_summary}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="https://beta.elevenidllc.com")
    parser.add_argument("--org-id", default="00000000-0000-0000-0000-000000000001")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        rendered = json.dumps(probe(args.base, args.org_id), indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
    except MetadataError as exc:
        raise SystemExit(f"Spruce metadata probe failed: {exc}") from exc


if __name__ == "__main__":
    main()
