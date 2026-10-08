#!/usr/bin/env python3
"""Provision real beta passport references through the staged signed Gateway."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

try:
    from .passport_beta_reference_intents import DurableReferenceRequests, _write_new
    from .passport_supported_flow_references import (
        PASSPORT_COMPLIANCE_PROFILE_ID, provision_beta_physical_passport_references,
    )
    from .passport_supported_flow_start import create_physical_passport_definition
    from .probe_passport_beta_aggregate_ceremony import (
        IDENTITY_ROUTE, gateway_post, staged_public_domain,
    )
    from .probe_passport_beta_aggregate_kms import checked_selection
    from .probe_passport_beta_host import HostProbeError, beta_psql, run
    from .probe_passport_beta_rust_owner_flow import checked_session, signed_service
    from .probe_passport_beta_rust_owner_write import checked_application
except ImportError:
    from passport_beta_reference_intents import DurableReferenceRequests, _write_new
    from passport_supported_flow_references import (
        PASSPORT_COMPLIANCE_PROFILE_ID, provision_beta_physical_passport_references,
    )
    from passport_supported_flow_start import create_physical_passport_definition
    from probe_passport_beta_aggregate_ceremony import (
        IDENTITY_ROUTE, gateway_post, staged_public_domain,
    )
    from probe_passport_beta_aggregate_kms import checked_selection
    from probe_passport_beta_host import HostProbeError, beta_psql, run
    from probe_passport_beta_rust_owner_flow import checked_session, signed_service
    from probe_passport_beta_rust_owner_write import checked_application


ROOT = Path(__file__).resolve().parents[1]
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
SAFE_PATH = re.compile(r"/v1/[A-Za-z0-9_/?=&-]{1,512}\Z")
SAFE_KEY = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
MAX_RESPONSE = 128 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def private_gateway_json(container: str, session: str, method: str, path: str,
                         body: dict[str, Any] | None, headers: dict[str, str]
                         ) -> tuple[int, Any]:
    """Use only the signed Gateway loopback listener while public ingress is down."""
    require(CONTAINER.fullmatch(container) is not None
            and method in ("GET", "POST")
            and SAFE_PATH.fullmatch(path) is not None
            and path.split("?", 1)[0].startswith((
                "/v1/credential-templates", "/v1/application-templates",
                "/v1/delivery-destinations", "/v1/flows/definitions",
            ))
            and bool(session) and not any(character in session for character in "\r\n\0")
            and set(headers) <= {"idempotency-key"}
            and all(SAFE_KEY.fullmatch(value) is not None for value in headers.values()),
            "Beta reference Gateway request is invalid")
    require((method == "POST") == (body is not None or path.endswith((
        "/activate", "/validate",
    ))), "Beta reference Gateway body is invalid")
    script = (
        'IFS= read -r cookie; [ -n "$cookie" ] || exit 4; '
        'exec curl --silent --show-error --max-time 55 --include '
        '-H "Accept: application/json" -H "Cookie: $cookie" '
        + ('-H "idempotency-key: $3" ' if headers else '')
        + ('-H "Content-Type: application/json" --data-binary @- '
           if body is not None else '')
        + '--request "$2" --url "$1"'
    )
    payload = session.encode() + b"\n"
    if body is not None:
        payload += json.dumps(body, separators=(",", ":")).encode()
    try:
        response = subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-ec", script, "sh",
             "http://127.0.0.1:8000" + path, method,
             headers.get("idempotency-key", "")],
            input=payload, capture_output=True, check=False, timeout=65,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HostProbeError("Beta reference Gateway request failed") from error
    require(response.returncode == 0 and len(response.stdout) <= MAX_RESPONSE,
            "Beta reference Gateway request failed")
    head, separator, raw = response.stdout.partition(b"\r\n\r\n")
    require(bool(separator) and head.startswith(b"HTTP/1.1 "),
            "Beta reference Gateway response is invalid")
    try:
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        result = json.loads(raw)
    except (IndexError, ValueError) as error:
        raise HostProbeError("Beta reference Gateway response is invalid") from error
    request_ids = [line.split(":", 1)[1].strip() for line in lines[1:]
                   if line.lower().startswith("x-request-id:")]
    require(len(request_ids) == 1 and 0 < len(request_ids[0]) <= 128
            and not any(character in request_ids[0] for character in "\r\n"),
            "Beta reference Gateway route trace is invalid")
    return status, result


def _private_path(path: Path) -> Path:
    require(path.is_absolute(), "Beta reference private path must be absolute")
    resolved = path.resolve()
    require(not resolved.is_relative_to(ROOT),
            "Beta reference private path must be outside protected source")
    return resolved


def _output(path: Path, value: dict[str, Any]) -> str:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if path.exists():
        require(path.read_bytes() == raw, "Beta reference output changed")
    else:
        _write_new(path, value)
    return hashlib.sha256(raw).hexdigest()


def provision(plan: dict[str, Any], selection: dict[str, str],
              session: str, dsc_session: str | None, intent_dir: Path,
              application_file: Path, flow_file: Path | None,
              *, phase: str) -> dict[str, Any]:
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and phase in ("references", "flow")
            and isinstance(plan.get("source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", plan["source_commit"]) is not None,
            "Beta reference plan is invalid")
    organization = selection["organization_id"]
    issuer_did = selection["dsc_issuer_did"]
    phase_name = beta_psql(
        "SELECT phase FROM passport_cutover.state WHERE singleton=true;",
        run, plan["postgres_container_id"],
    )
    require((phase_name in ("fully_fenced", "rust_owner")
             if phase == "references" else phase_name == "rust_owner"),
            "Beta reference owner phase is invalid")
    domain = staged_public_domain(plan, run)
    require(issuer_did.startswith(f"did:web:{domain}:orgs:"),
            "Beta passport issuer is outside the managed domain")
    gateway = signed_service(plan, "gateway", run)
    signed_service(plan, "flow", run)
    prefix = ("Beta passport " + plan["source_commit"][:12] + " "
              + hashlib.sha256(str(intent_dir).encode()).hexdigest()[:10])
    request = DurableReferenceRequests(
        lambda method, path, body, headers: private_gateway_json(
            gateway, session, method, path, body, headers,
        ),
        intent_dir, source_commit=plan["source_commit"],
        gateway_container_id=gateway, organization_id=organization,
        allow_new=phase == "flow" or phase_name == "fully_fenced",
    )
    if phase == "references":
        require(dsc_session is not None and flow_file is None,
                "Beta reference issuer authority is missing")
        if phase_name == "fully_fenced":
            body = {"organization_id": organization, "issuer_did": issuer_did,
                    "key_purpose": "x509_doc_signer", "credential_format": "ICAO_EMRTD",
                    "algorithm": "ES256"}
            status, result, _ = gateway_post(
                gateway, IDENTITY_ROUTE, organization, dsc_session, body,
            )
            identity = result.get("identity")
            require(status == 200 and isinstance(identity, dict)
                    and all(identity.get(field) == value for field, value in body.items()
                            if field != "organization_id")
                    and identity.get("status") == "active",
                    "Beta DSC issuer profile is invalid")
        else:
            require(application_file.is_file()
                    and all((intent_dir / (key + ".json")).is_file()
                            for key in ("credential", "application", "destination")),
                    "Beta reference resume lacks sealed pretransition state")
        refs = provision_beta_physical_passport_references(
            request, organization, prefix, issuer_did,
            "passport-" + hashlib.sha256(str(intent_dir).encode()).hexdigest()[:24],
            PASSPORT_COMPLIANCE_PROFILE_ID,
        )
        output = {"organization_id": organization, "issuer_did": issuer_did, **refs}
        digest = _output(application_file, output)
        return {"schema": "marty.passport-beta-reference-provision/v1",
                "phase": phase, "source_commit": plan["source_commit"],
                "gateway_container_id": gateway, "application_file_sha256": digest,
                "verified": True}
    require(flow_file is not None and dsc_session is None,
            "Beta Flow output is invalid")
    application, application_digest = checked_application(application_file)
    require(application["organization_id"] == organization
            and application["issuer_did"] == issuer_did,
            "Beta Flow application binding changed")
    definition_id = create_physical_passport_definition(
        lambda method, path, body: request(method, path, body, {}),
        organization, prefix + " flow", application, resume=True,
    )
    digest = _output(flow_file, {
        "organization_id": organization,
        "flow_definition_id": definition_id,
        "issuer_did": issuer_did,
    })
    require(signed_service(plan, "gateway", run) == gateway,
            "Beta reference Gateway changed during provisioning")
    return {"schema": "marty.passport-beta-reference-provision/v1",
            "phase": phase, "source_commit": plan["source_commit"],
            "gateway_container_id": gateway,
            "application_file_sha256": application_digest,
            "flow_file_sha256": digest, "verified": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--issuer-chain-file", required=True, type=Path)
    parser.add_argument("--session-file", required=True, type=Path)
    parser.add_argument("--dsc-session-file", type=Path)
    parser.add_argument("--intent-dir", required=True, type=Path)
    parser.add_argument("--application-file", required=True, type=Path)
    parser.add_argument("--flow-file", type=Path)
    parser.add_argument("--phase", required=True, choices=("references", "flow"))
    args = parser.parse_args()
    try:
        plan_path = _private_path(args.plan)
        selection_path = _private_path(args.issuer_chain_file)
        session_path = _private_path(args.session_file)
        intent_dir = _private_path(args.intent_dir)
        application_file = _private_path(args.application_file)
        flow_file = _private_path(args.flow_file) if args.flow_file else None
        dsc_path = _private_path(args.dsc_session_file) if args.dsc_session_file else None
        plan = json.loads(plan_path.read_bytes())
        selection, _ = checked_selection(selection_path)
        session = checked_session(session_path)
        dsc_session = checked_session(dsc_path) if dsc_path else None
        result = provision(plan, selection, session, dsc_session, intent_dir,
                           application_file, flow_file, phase=args.phase)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        raise SystemExit(f"Beta reference provisioning failed: {error}") from error
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
