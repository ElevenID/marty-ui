#!/usr/bin/env python3
"""Verify that the already-running beta actually enables portable Canvas.

The acceptance runner shares Docker Desktop with the development beta.  This
preflight deliberately inspects the deployed issuance/worker containers rather
than trusting environment variables attached to the GitHub job.  It emits only
boolean/check metadata; signer configuration and container environment values
never enter the artifact bundle.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MARTY_ORIGIN = "https://beta.elevenidllc.com"
CANVAS_ORIGIN = "https://canvas-test.elevenidllc.com"
ISSUANCE_CONTAINER = "marty-issuance"
WORKER_CONTAINER = "marty-canvas-sync-worker"
PRIVATE_RSA_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth"}


class CapabilityError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CapabilityError(message)


def _docker_json(*args: str) -> Any:
    try:
        result = subprocess.run(
            ["docker", *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        # Never attach captured docker output: inspect output can contain the
        # complete beta environment, including secrets unrelated to Canvas.
        subject = args[-1] if args else "beta runtime"
        raise CapabilityError(f"Docker inspection failed for {subject}") from exc


def _container(name: str) -> tuple[dict[str, str], str, str]:
    payload = _docker_json("inspect", name)
    _require(isinstance(payload, list) and len(payload) == 1, f"{name} inspection was ambiguous")
    record = payload[0]
    state = record.get("State") if isinstance(record, dict) else None
    config = record.get("Config") if isinstance(record, dict) else None
    _require(isinstance(state, dict) and state.get("Running") is True, f"{name} is not running")
    if isinstance(state.get("Health"), dict):
        _require(state["Health"].get("Status") == "healthy", f"{name} is not healthy")
    _require(isinstance(config, dict), f"{name} configuration is missing")
    entries = config.get("Env")
    _require(isinstance(entries, list), f"{name} environment is missing")
    env: dict[str, str] = {}
    for item in entries:
        if not isinstance(item, str) or "=" not in item:
            continue
        key, value = item.split("=", 1)
        env[key] = value
    image_id = str(record.get("Image") or "")
    configured_image = str(config.get("Image") or "")
    return env, image_id, configured_image


def _csv(value: str, setting: str) -> list[str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    _require(len(items) == len(set(items)), f"{setting} contains duplicates")
    return items


def _validate_jwks(raw: str, active_kid: str) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CapabilityError("Deployed Canvas tool JWKS is not valid JSON") from exc
    keys = payload.get("keys") if isinstance(payload, dict) else None
    _require(isinstance(keys, list) and keys, "Deployed Canvas tool JWKS has no keys")
    by_kid: dict[str, dict[str, Any]] = {}
    for key in keys:
        _require(isinstance(key, dict), "Deployed Canvas tool JWKS contains a non-object key")
        _require(not PRIVATE_RSA_PARAMETERS.intersection(key), "Deployed Canvas tool JWKS contains private RSA material")
        _require(
            key.get("kty") == "RSA"
            and key.get("alg") == "RS256"
            and key.get("use") == "sig"
            and bool(key.get("n"))
            and bool(key.get("e")),
            "Every deployed Canvas tool key must be a public RSA/RS256 signing key",
        )
        kid = str(key.get("kid") or "").strip()
        _require(bool(kid) and kid not in by_kid, "Deployed Canvas tool JWKS kids must be unique and non-empty")
        by_kid[kid] = key
    _require(active_kid in by_kid, "Deployed Canvas active kid is absent from its JWKS")
    return by_kid


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _public_jwks() -> dict[str, dict[str, Any]]:
    url = f"{MARTY_ORIGIN}/v1/integrations/canvas/lti/jwks"
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": "canvas-oss-portability/1"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=20) as response:
            _require(response.status == 200, "Public Canvas LTI JWKS endpoint did not return 200")
            _require(response.geturl() == url, "Public Canvas LTI JWKS endpoint redirected")
            raw = response.read().decode("utf-8")
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise CapabilityError("Public beta Canvas LTI JWKS endpoint is unavailable") from exc
    # The public document has no separate active-kid field; validate structure
    # here and compare exact public parameters to the locally inspected config.
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CapabilityError("Public beta Canvas LTI JWKS is not valid JSON") from exc
    keys = payload.get("keys") if isinstance(payload, dict) else None
    _require(isinstance(keys, list) and keys, "Public beta Canvas LTI JWKS has no keys")
    by_kid: dict[str, dict[str, Any]] = {}
    for key in keys:
        _require(isinstance(key, dict), "Public beta Canvas LTI JWKS contains a non-object key")
        _require(not PRIVATE_RSA_PARAMETERS.intersection(key), "Public beta Canvas LTI JWKS exposes private RSA material")
        kid = str(key.get("kid") or "").strip()
        _require(bool(kid) and kid not in by_kid, "Public beta Canvas LTI JWKS kids are invalid")
        by_kid[kid] = key
    return by_kid


def validate(expected_organization_id: str) -> dict[str, Any]:
    _require(bool(expected_organization_id.strip()), "Expected pilot organization ID is required")
    issuance, issuance_image, issuance_reference = _container(ISSUANCE_CONTAINER)
    worker, worker_image, worker_reference = _container(WORKER_CONTAINER)
    _require(issuance_image == worker_image, "Canvas worker is not running the deployed issuance image")
    _require(issuance_reference == worker_reference, "Canvas worker and issuance image references differ")

    _require(issuance.get("CANVAS_PORTABLE_INTEGRATION_ENABLED", "").lower() == "true", "Portable Canvas is not enabled in deployed beta issuance")
    pilot_orgs = _csv(issuance.get("CANVAS_PILOT_ORGANIZATION_IDS", ""), "CANVAS_PILOT_ORGANIZATION_IDS")
    _require("*" not in pilot_orgs and expected_organization_id in pilot_orgs, "Expected organization is not explicitly admitted to the deployed Canvas pilot")
    _require(issuance.get("CANVAS_LTI_EXPERIENCE_BASE_URL") == MARTY_ORIGIN, "Deployed Canvas experience base URL is not the beta origin")
    _require(
        issuance.get("CANVAS_OAUTH_COMPLETION_REDIRECT_URL")
        == f"{MARTY_ORIGIN}/console/org/deploy/canvas",
        "Deployed Canvas OAuth completion URL is not the Canvas console route",
    )
    self_managed = _csv(issuance.get("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", ""), "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST")
    _require(CANVAS_ORIGIN in self_managed, "Deployed beta does not allowlist the exact self-managed Canvas origin")
    _require(issuance.get("CANVAS_LEGACY_EVENT_INGEST_ENABLED", "false").lower() == "false", "Legacy Canvas event ingestion must remain disabled")
    _require(issuance.get("CANVAS_ALLOW_PRIVATE_BASE_URLS", "false").lower() == "false", "Private Canvas base URLs must remain disabled")
    _require(issuance.get("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS", "false").lower() == "false", "HTTP Canvas base URLs must remain disabled")
    _require(
        issuance.get("CANVAS_BINDING_READINESS_MAX_AGE_SECONDS") == "900",
        "Deployed beta Canvas readiness/KMS challenge TTL must be 900 seconds",
    )
    _require(
        issuance.get("CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS") == "900",
        "Deployed beta Canvas issuance evidence TTL must be 900 seconds",
    )

    signer_settings = (
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
        "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID",
        "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE",
        "CANVAS_LTI_TOOL_ACTIVE_KID",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS",
        "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES",
    )
    for setting in signer_settings:
        _require(bool(issuance.get(setting, "").strip()), f"Deployed beta issuance is missing {setting}")
        _require(worker.get(setting) == issuance.get(setting), f"Canvas worker {setting} differs from deployed issuance")
    _require(
        issuance["CANVAS_LTI_TOOL_SIGNING_SERVICE_ID"] == "managed-openbao-transit",
        "Beta portability requires the managed OpenBao signing service",
    )
    lti_reference = issuance["CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE"].strip()
    _require(lti_reference.startswith("lti-tool-"), "Managed OpenBao LTI signing key must use the lti-tool- namespace")
    credential_references = set(_csv(issuance["CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES"], "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES"))
    _require(lti_reference not in credential_references, "LTI signing key overlaps a credential issuer key")
    configured_jwks = _validate_jwks(
        issuance["CANVAS_LTI_TOOL_PUBLIC_JWKS"],
        issuance["CANVAS_LTI_TOOL_ACTIVE_KID"].strip(),
    )
    public_jwks = _public_jwks()
    _require(set(public_jwks) == set(configured_jwks), "Public beta JWKS key set differs from deployed signer configuration")
    for kid, configured in configured_jwks.items():
        for parameter in ("kty", "kid", "alg", "use", "n", "e"):
            _require(public_jwks[kid].get(parameter) == configured.get(parameter), "Public beta JWKS differs from deployed signer configuration")

    for setting in (
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
    ):
        _require(worker.get(setting) == issuance.get(setting), f"Canvas worker {setting} differs from deployed issuance")
    processor = worker.get("CANVAS_SYNC_PROCESSOR", "")
    module, separator, function = processor.partition(":")
    _require(bool(module and separator and function), "Deployed Canvas worker processor is invalid")
    _require(
        worker.get("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS") == "600",
        "Deployed Canvas worker absolute job deadline must be 600 seconds",
    )

    return {
        "schema_version": 1,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "beta_origin": MARTY_ORIGIN,
        "canvas_origin": CANVAS_ORIGIN,
        "checks": {
            "portable_feature_enabled": True,
            "pilot_organization_admitted": True,
            "self_managed_origin_allowlisted": True,
            "legacy_event_ingest_disabled": True,
            "dedicated_managed_openbao_rs256_signer": True,
            "public_jwks_matches_deployment": True,
            "credential_and_lti_keys_distinct": True,
            "canvas_worker_running_same_image": True,
            "readiness_and_evidence_ttls_fail_closed": True,
            "worker_job_deadline_fail_closed": True,
        },
        "composite_binding_readiness_required": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = validate(args.organization_id)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except CapabilityError as exc:
        print(f"Canvas beta capability preflight failed: {exc}", file=sys.stderr)
        return 1
    print("Canvas beta capability preflight passed; binding composite readiness remains required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
