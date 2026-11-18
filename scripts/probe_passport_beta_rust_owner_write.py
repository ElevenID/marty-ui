#!/usr/bin/env python3
"""Prove a private Rust passport write before the beta ingress starts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
from uuid import UUID

try:
    from .probe_passport_beta_batch import SYNTHETIC_DOCUMENT
    from .probe_passport_beta_host import HostProbeError, beta_psql, inspect, run
    from .verify_passport_beta_rust_owner import verify as verify_rust_owner
except ImportError:
    from probe_passport_beta_batch import SYNTHETIC_DOCUMENT
    from probe_passport_beta_host import HostProbeError, beta_psql, inspect, run
    from verify_passport_beta_rust_owner import verify as verify_rust_owner


IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
MAX_RESPONSE = 64 * 1024
APPLICATION_FIELDS = frozenset({
    "organization_id", "issuer_did", "application_template_id",
    "credential_template_id", "delivery_destination_profile_id",
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def private_request(command: list[str], body: bytes) -> bytes:
    try:
        result = subprocess.run(command, input=body, capture_output=True,
                                check=False, timeout=45)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostProbeError("Private Rust passport request failed") from exc
    require(result.returncode == 0 and len(result.stdout) <= MAX_RESPONSE,
            "Private Rust passport request failed")
    return result.stdout


def checked_application(path: Path) -> tuple[dict[str, str], str]:
    require(path.is_absolute(), "Private Rust passport application path is not absolute")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Private Rust passport application is unreadable") from exc
    require(isinstance(value, dict) and set(value) == APPLICATION_FIELDS,
            "Private Rust passport application fields are invalid")
    require(all(isinstance(value.get(field), str)
                and IDENTIFIER.fullmatch(value[field]) is not None
                for field in APPLICATION_FIELDS - {"issuer_did"})
            and isinstance(value.get("issuer_did"), str)
            and value["issuer_did"].startswith("did:")
            and len(value["issuer_did"]) <= 255
            and not any(char in value["issuer_did"] for char in "\r\n\0"),
            "Private Rust passport application identity is invalid")
    return value, hashlib.sha256(raw).hexdigest()


def checked_uuid(value: Any) -> str:
    require(isinstance(value, str), "Private Rust passport job identity is invalid")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise HostProbeError("Private Rust passport job identity is invalid") from exc
    require(str(parsed) == value, "Private Rust passport job identity is invalid")
    return value


def durable_dispatch_marker(path: Path, marker: dict[str, Any]) -> None:
    """Seal the attempt before the request; an uncertain send cannot be replayed."""
    raw = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise HostProbeError("Private Rust passport dispatch marker could not be sealed") from exc


def database_row(plan: dict[str, Any], organization_id: str,
                 flow_execution_id: str, job_id: str,
                 runner: Callable[[list[str]], str]) -> str:
    require(IDENTIFIER.fullmatch(organization_id) is not None
            and IDENTIFIER.fullmatch(flow_execution_id) is not None,
            "Private Rust passport row selector is invalid")
    job_id = checked_uuid(job_id)
    sql = (
        "SELECT application_id || '|' || status FROM "
        "issuance_service.physical_document_jobs WHERE "
        f"id='{job_id}' AND organization_id='{organization_id}' "
        f"AND flow_execution_id='{flow_execution_id}' "
        "AND secure_artifact_ciphertext IS NOT NULL "
        "AND length(secure_artifact_ciphertext)>0"
    )
    return beta_psql(sql, runner, plan["postgres_container_id"])


def attempted_row(plan: dict[str, Any], organization_id: str,
                  flow_execution_id: str,
                  runner: Callable[[list[str]], str]) -> tuple[str, str] | None:
    require(IDENTIFIER.fullmatch(organization_id) is not None
            and IDENTIFIER.fullmatch(flow_execution_id) is not None,
            "Private Rust passport attempt selector is invalid")
    sql = (
        "SELECT id || '|' || application_id || '|' || status FROM "
        "issuance_service.physical_document_jobs WHERE "
        f"organization_id='{organization_id}' "
        f"AND flow_execution_id='{flow_execution_id}' "
        "AND secure_artifact_ciphertext IS NOT NULL "
        "AND length(secure_artifact_ciphertext)>0"
    )
    raw = beta_psql(sql, runner, plan["postgres_container_id"])
    if not raw:
        return None
    rows = raw.splitlines()
    require(len(rows) == 1, "Private Rust passport attempt is ambiguous")
    fields = rows[0].split("|")
    require(len(fields) == 3 and fields[2] == "DRAFT",
            "Private Rust passport attempt state changed")
    return checked_uuid(fields[0]), checked_uuid(fields[1])


def probe(plan: dict[str, Any], application: dict[str, str],
          application_sha256: str, *,
          flow_execution_id: str,
          allow_post: bool,
          expected_transition_txid: str,
          runner: Callable[[list[str]], str] = run,
          request: Callable[[list[str], bytes], bytes] = private_request,
          owner_verifier: Callable[..., dict[str, Any]] = verify_rust_owner,
          existing: dict[str, Any] | None = None,
          dispatch_marker: dict[str, Any] | None = None,
          before_post: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    owner = owner_verifier(plan, runner=runner)
    require(owner.get("verified") is True
            and owner.get("source_commit") == plan.get("source_commit")
            and owner.get("postgres_container_id") == plan.get("postgres_container_id"),
            "Private Rust passport owner changed")
    service_ids = plan.get("old_container_ids_by_service")
    require(isinstance(service_ids, dict),
            "Private Rust passport old generation is invalid")
    container = str(plan.get("private_issuance_container_id", ""))
    if not container:
        # The operator selects this from the current Compose label, never from
        # the old Python writer identity pinned in the plan.
        raw = runner(["docker", "ps", "--filter",
                      "label=com.docker.compose.project=elevenid-beta", "--filter",
                      "label=com.docker.compose.service=issuance-native",
                      "--format", "{{.ID}}"])
        candidates = raw.splitlines()
        require(len(candidates) == 1 and re.fullmatch(r"[0-9a-f]{12,64}", candidates[0])
                is not None, "Private Rust issuance generation is ambiguous")
        container = candidates[0]
    record = inspect(container, runner)
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    state = record.get("State")
    container = record.get("Id")
    require(isinstance(container, str) and CONTAINER.fullmatch(container) is not None
            and container != service_ids.get("issuance-native")
            and isinstance(config, dict) and isinstance(labels, dict)
            and labels.get("com.docker.compose.project") == "elevenid-beta"
            and labels.get("com.docker.compose.service") == "issuance-native"
            and config.get("Image") == plan.get("services_image")
            and isinstance(state, dict) and state.get("Running") is True
            and state.get("Status") == "running",
            "Private Rust issuance image or process changed")
    require(re.fullmatch(r"[0-9a-f]{64}", application_sha256) is not None,
            "Private Rust application digest is invalid")
    require(str(owner.get("transition_txid")) == expected_transition_txid
            and re.fullmatch(r"[0-9]+", expected_transition_txid) is not None,
            "Private Rust passport transition changed")
    require(isinstance(flow_execution_id, str)
            and re.fullmatch(r"rust-owner-[0-9a-f]{32}", flow_execution_id)
                is not None,
            "Private Rust passport attempt identity is invalid")
    expected_marker = {
        "schema": "marty.passport-beta-rust-owner-dispatch/v1",
        "source_commit": plan["source_commit"],
        "transition_txid": expected_transition_txid,
        "application_file_sha256": application_sha256,
        "flow_execution_id": flow_execution_id,
        "issuance_container_id": container,
    }
    require(dispatch_marker is None or dispatch_marker == expected_marker,
            "Private Rust passport dispatch differs from signed attempt")
    if existing is None:
        flow = flow_execution_id
        recovered = attempted_row(plan, application["organization_id"], flow, runner)
        if recovered is not None:
            job_id, application_id = recovered
        else:
            require(allow_post and dispatch_marker is None
                    and before_post is not None,
                    "Earlier private Rust passport request has no resolved database row")
            before_post(expected_marker)
            body = {**application, **SYNTHETIC_DOCUMENT, "flow_execution_id": flow}
            script = (
                'test -n "$GRPC_SERVICE_TOKEN"; '
                'curl --silent --show-error --max-time 30 '
                '--write-out "\\n%{http_code}" '
                '--header "Content-Type: application/json" '
                '--header "Accept: application/json" '
                '--header "x-organization-id: ' + application["organization_id"] + '" '
                '--header "x-api-key: $GRPC_SERVICE_TOKEN" '
                '--data-binary @- '
                '--url http://127.0.0.1:8005/v1/passport/applications'
            )
            raw = request(["docker", "exec", "-i", container, "sh", "-ec", script],
                          json.dumps(body, separators=(",", ":")).encode())
            require(len(raw) <= MAX_RESPONSE, "Private Rust passport response is oversized")
            try:
                response, status = raw.rsplit(b"\n", 1)
                result = json.loads(response)
            except (ValueError, TypeError) as exc:
                raise HostProbeError("Private Rust passport response is invalid") from exc
            require(status == b"201" and isinstance(result, dict)
                    and result.get("organization_id") == application["organization_id"]
                    and result.get("flow_execution_id") == flow
                    and result.get("status") == "DRAFT",
                    "Private Rust passport creation did not persist a draft")
            job_id = checked_uuid(result.get("id"))
            application_id = checked_uuid(result.get("application_id"))
    else:
        require(existing.get("schema") == "marty.passport-beta-rust-owner-write/v1"
                and existing.get("source_commit") == plan.get("source_commit")
                and existing.get("application_file_sha256") == application_sha256
                and existing.get("issuance_container_id") == container
                and existing.get("transition_txid") == owner.get("transition_txid"),
                "Private Rust passport receipt differs from current generation")
        job_id = checked_uuid(existing.get("job_id"))
        application_id = checked_uuid(existing.get("application_id"))
        flow = existing.get("flow_execution_id")
        require(flow == flow_execution_id,
                "Private Rust passport receipt flow is invalid")
    row = database_row(plan, application["organization_id"], flow, job_id, runner)
    require(row == f"{application_id}|DRAFT",
            "Private Rust passport database row differs from HTTP response")
    refreshed = owner_verifier(plan, runner=runner)
    require(refreshed == owner, "Rust owner changed during private write proof")
    return {
        "schema": "marty.passport-beta-rust-owner-write/v1",
        "source_commit": plan["source_commit"],
        "transition_txid": owner["transition_txid"],
        "application_file_sha256": application_sha256,
        "issuance_container_id": container,
        "job_id": job_id,
        "application_id": application_id,
        "flow_execution_id": flow,
        "database_row_verified": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--application-file", required=True, type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--intent", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        application, digest = checked_application(args.application_file)
        require(isinstance(plan, dict), "Private Rust passport plan is invalid")
        if args.validate_only:
            require(args.receipt is None, "Private Rust validation cannot use a receipt")
            result = {"schema": "marty.passport-beta-rust-owner-input/v1",
                      "source_commit": plan.get("source_commit"),
                      "application_file_sha256": digest}
        else:
            require(args.intent is not None, "Private Rust passport intent is required")
            intent = json.loads(args.intent.read_text(encoding="utf-8"))
            require(isinstance(intent, dict)
                    and intent.get("schema") == "marty.passport-beta-rust-owner-write-intent/v1"
                    and intent.get("source_commit") == plan.get("source_commit")
                    and intent.get("application_file_sha256") == digest,
                    "Private Rust passport intent differs from input")
            existing = (json.loads(args.receipt.read_text(encoding="utf-8"))
                        if args.receipt and args.receipt.exists() else None)
            require(existing is None or isinstance(existing, dict),
                    "Private Rust passport receipt is invalid")
            marker_path = Path(str(args.intent) + ".dispatch.json")
            dispatch_marker = (json.loads(marker_path.read_text(encoding="utf-8"))
                               if marker_path.exists() else None)
            require(dispatch_marker is None or isinstance(dispatch_marker, dict),
                    "Private Rust passport dispatch marker is invalid")
            result = probe(plan, application, digest,
                           flow_execution_id=intent.get("flow_execution_id"),
                           allow_post=dispatch_marker is None,
                           expected_transition_txid=str(intent.get("transition_txid")),
                           existing=existing, dispatch_marker=dispatch_marker,
                           before_post=lambda marker: durable_dispatch_marker(
                               marker_path, marker))
            require(intent.get("transition_txid") == result["transition_txid"],
                    "Private Rust passport intent transition changed")
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Private Rust passport write proof failed: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
