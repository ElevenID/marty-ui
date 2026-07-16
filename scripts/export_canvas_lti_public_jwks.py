#!/usr/bin/env python3
"""Export a public, rotation-aware JWKS from OpenBao Transit key metadata."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def export_public_jwks(document: dict[str, Any], *, key_name: str) -> tuple[dict[str, Any], str]:
    data = document.get("data")
    if not isinstance(data, dict):
        raise ValueError("OpenBao response is missing data")
    if data.get("name") != key_name:
        raise ValueError("OpenBao response key name does not match the requested LTI key")
    if not str(data.get("type", "")).startswith("rsa-"):
        raise ValueError("Canvas LTI tool signing key must be RSA")

    latest_version = data.get("latest_version")
    if not isinstance(latest_version, int) or latest_version < 1:
        raise ValueError("OpenBao response has no valid latest_version")
    versions = data.get("keys")
    if not isinstance(versions, dict) or str(latest_version) not in versions:
        raise ValueError("OpenBao response is missing the active public key version")

    parsed_versions: list[tuple[int, dict[str, Any], datetime]] = []
    for raw_version, raw_metadata in versions.items():
        try:
            version = int(raw_version)
        except (TypeError, ValueError) as exc:
            raise ValueError("OpenBao key version must be an integer") from exc
        if not isinstance(raw_metadata, dict):
            raise ValueError(f"OpenBao key version {version} metadata is invalid")
        created_at = _parse_timestamp(
            raw_metadata.get("creation_time"), field=f"keys.{version}.creation_time"
        )
        parsed_versions.append((version, raw_metadata, created_at))
    parsed_versions.sort(key=lambda item: item[0])

    exported: list[dict[str, Any]] = []
    for index, (version, metadata, _created_at) in enumerate(parsed_versions):
        public_pem = metadata.get("public_key")
        if not isinstance(public_pem, str) or "PRIVATE KEY" in public_pem:
            raise ValueError(f"OpenBao key version {version} has no safe public key")
        try:
            public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"OpenBao key version {version} public key is invalid") from exc
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError(f"OpenBao key version {version} is not RSA")
        numbers = public_key.public_numbers()
        key: dict[str, Any] = {
            "alg": "RS256",
            "e": _b64url_uint(numbers.e),
            "kid": f"{key_name}-v{version}",
            "kty": "RSA",
            "n": _b64url_uint(numbers.n),
            "use": "sig",
        }
        if version != latest_version:
            if index + 1 >= len(parsed_versions):
                raise ValueError("Cannot determine when a prior key version was retired")
            retired_at = parsed_versions[index + 1][2]
            key["retired_at"] = retired_at.isoformat().replace("+00:00", "Z")
        exported.append(key)

    active_kid = f"{key_name}-v{latest_version}"
    exported.sort(key=lambda key: key["kid"] != active_kid)
    return {"keys": exported}, active_kid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--active-kid-output", required=True, type=Path)
    parser.add_argument("--key-name", default="lti-tool-marty-rs256")
    args = parser.parse_args()

    # Windows PowerShell 5.1's `Set-Content -Encoding utf8` includes a BOM.
    source = json.loads(args.input.read_text(encoding="utf-8-sig"))
    jwks, active_kid = export_public_jwks(source, key_name=args.key_name)
    args.output.write_text(json.dumps(jwks, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    args.active_kid_output.write_text(active_kid, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
