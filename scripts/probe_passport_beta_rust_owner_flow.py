#!/usr/bin/env python3
"""Prove a private Gateway -> Rust Flow -> native passport write.

The caller must start Gateway on its loopback listener while the public edge
remains closed.  A durable intent is required before the first POST; a retry
never sends a second POST when the first response was lost.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
from uuid import UUID

try:
    from .probe_passport_beta_batch import SYNTHETIC_DOCUMENT
    from .probe_passport_beta_host import HostProbeError, beta_psql, inspect, run
    from .probe_passport_beta_rust_owner_write import (
        checked_application, durable_dispatch_marker,
    )
    from .verify_passport_beta_rust_owner import verify as verify_rust_owner
except ImportError:
    from probe_passport_beta_batch import SYNTHETIC_DOCUMENT
    from probe_passport_beta_host import HostProbeError, beta_psql, inspect, run
    from probe_passport_beta_rust_owner_write import (
        checked_application, durable_dispatch_marker,
    )
    from verify_passport_beta_rust_owner import verify as verify_rust_owner


IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
REFERENCE = re.compile(r"rust-owner-flow-[0-9a-f]{32}\Z")
MAX_RESPONSE = 128 * 1024
FLOW_FIELDS = frozenset({"organization_id", "flow_definition_id", "issuer_did"})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def checked_uuid(value: Any) -> str:
    require(isinstance(value, str), "Private Flow identity is invalid")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise HostProbeError("Private Flow identity is invalid") from exc
    require(str(parsed) == value, "Private Flow identity is not canonical")
    return value


def checked_flow(path: Path) -> tuple[dict[str, str], str]:
    require(path.is_absolute(), "Private Flow input path is not absolute")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Private Flow input is unreadable") from exc
    require(isinstance(value, dict) and set(value) == FLOW_FIELDS
            and all(isinstance(value.get(key), str)
                    and IDENTIFIER.fullmatch(value[key]) is not None
                    for key in ("organization_id", "flow_definition_id"))
            and isinstance(value.get("issuer_did"), str)
            and value["issuer_did"].startswith("did:")
            and len(value["issuer_did"]) <= 255
            and not any(char in value["issuer_did"] for char in "\r\n\0"),
            "Private Flow input identity is invalid")
    return value, hashlib.sha256(raw).hexdigest()


def checked_session(path: Path) -> str:
    require(path.is_absolute(), "Private Flow session path is not absolute")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HostProbeError("Private Flow session is unreadable") from exc
    require(bool(value) and len(value) <= 8192
            and not any(ord(char) < 32 or ord(char) == 127 for char in value),
            "Private Flow session is invalid")
    return value


def private_gateway_request(container: str, method: str, path: str,
                            session: str, body: dict[str, Any] | None) -> tuple[int, dict[str, Any], str]:
    require(CONTAINER.fullmatch(container) is not None
            and method in ("GET", "POST")
            and (path == "/v1/flows/instances" or re.fullmatch(
                r"/v1/flows/instances/[0-9a-f-]{36}", path) is not None
                 or re.fullmatch(r"/v1/flows/definitions/[A-Za-z0-9_-]{1,128}"
                                 r"(?:/validate)?", path) is not None
                 or re.fullmatch(r"/v1/credential-templates/[A-Za-z0-9_-]{1,128}",
                                 path) is not None),
            "Private Gateway route is invalid")
    require(bool(session) and "\n" not in session and "\r" not in session,
            "Private Gateway session is invalid")
    script = (
        'IFS= read -r cookie; '
        'curl --silent --show-error --max-time 45 --include '
        '--header "Accept: application/json" '
        '--header "Cookie: $cookie" '
        + ('--header "Content-Type: application/json" --data-binary @- '
           if method == "POST" else '')
        + f'--request {method} --url http://127.0.0.1:8000{path}'
    )
    payload = (session + "\n").encode() + (json.dumps(body, separators=(",", ":")).encode()
                                           if body is not None else b"")
    try:
        result = subprocess.run(["docker", "exec", "-i", container, "sh", "-ec", script],
                                input=payload, capture_output=True, check=False, timeout=55)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostProbeError("Private Gateway request failed") from exc
    require(result.returncode == 0 and len(result.stdout) <= MAX_RESPONSE,
            "Private Gateway request failed")
    head, sep, raw = result.stdout.partition(b"\r\n\r\n")
    require(bool(sep) and head.startswith(b"HTTP/1.1 "),
            "Private Gateway response is invalid")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
        response = json.loads(raw)
    except (IndexError, ValueError) as exc:
        raise HostProbeError("Private Gateway response is invalid") from exc
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.lower()] = value.strip()
    request_id = headers.get("x-request-id", "")
    require(isinstance(response, dict) and bool(request_id)
            and len(request_id) <= 128 and "\n" not in request_id,
            "Private Gateway response has no route trace")
    return status, response, request_id


def signed_service(plan: dict[str, Any], service: str,
                   runner: Callable[[list[str]], str]) -> str:
    output = runner(["docker", "ps", "--filter",
                     "label=com.docker.compose.project=elevenid-beta", "--filter",
                     f"label=com.docker.compose.service={service}", "--format", "{{.ID}}"])
    candidates = output.splitlines()
    require(len(candidates) == 1 and re.fullmatch(r"[0-9a-f]{12,64}", candidates[0]) is not None,
            f"Private {service} process is ambiguous")
    record = inspect(candidates[0], runner)
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    state = record.get("State")
    container = record.get("Id")
    old = plan.get("old_container_ids_by_service")
    require(isinstance(container, str) and CONTAINER.fullmatch(container) is not None
            and isinstance(old, dict) and container != old.get(service)
            and isinstance(config, dict) and isinstance(labels, dict)
            and labels.get("com.docker.compose.project") == "elevenid-beta"
            and labels.get("com.docker.compose.service") == service
            and config.get("Image") == plan.get("services_image")
            and isinstance(state, dict) and state.get("Running") is True
            and state.get("Status") == "running",
            f"Private {service} signed process changed")
    return container


def matching_instance(plan: dict[str, Any], flow: dict[str, str],
                      reference: str, runner: Callable[[list[str]], str]) -> str | None:
    require(REFERENCE.fullmatch(reference) is not None,
            "Private Flow intent reference is invalid")
    sql = (
        "SELECT id FROM flow_service.flow_instances WHERE "
        f"organization_id='{flow['organization_id']}' AND "
        f"flow_definition_id='{flow['flow_definition_id']}' AND "
        f"external_reference='{reference}'"
    )
    rows = beta_psql(sql, runner, plan["postgres_container_id"]).splitlines()
    require(len(rows) <= 1, "Private Flow intent matched multiple instances")
    return checked_uuid(rows[0]) if rows else None


def validate_live_references(plan: dict[str, Any], flow: dict[str, str],
                             application: dict[str, str], session: str, *,
                             runner: Callable[[list[str]], str] = run,
                             request: Callable[[str, str, str, str, dict[str, Any] | None],
                                               tuple[int, dict[str, Any], str]] = private_gateway_request,
                             ) -> dict[str, Any]:
    """Check tenant, active references and issuer before committing rust_owner."""
    require(flow["organization_id"] == application.get("organization_id")
            and flow["issuer_did"] == application.get("issuer_did"),
            "Private Flow and application tenant or issuer differ")
    gateway = signed_service(plan, "gateway", runner)
    flow_container = signed_service(plan, "flow", runner)
    base = f"/v1/flows/definitions/{flow['flow_definition_id']}"
    status, definition, definition_request_id = request(gateway, "GET", base,
                                                         session, None)
    require(status == 200 and definition.get("id") == flow["flow_definition_id"]
            and definition.get("organization_id") == flow["organization_id"]
            and definition.get("flow_type") == "physical_document_issuance"
            and definition.get("status") == "ACTIVE"
            and all(definition.get(field) == application.get(field)
                    for field in ("credential_template_id", "application_template_id",
                                  "delivery_destination_profile_id")),
            "Private Flow definition or application references are stale")
    status, validation, validation_request_id = request(gateway, "POST",
                                                         base + "/validate", session, None)
    require(status == 200 and validation.get("valid") is True
            and validation.get("errors") == [],
            "Private Flow live reference validation failed")
    template_path = f"/v1/credential-templates/{application['credential_template_id']}"
    status, template, template_request_id = request(gateway, "GET", template_path,
                                                     session, None)
    require(status == 200 and template.get("id") == application["credential_template_id"]
            and template.get("organization_id") == flow["organization_id"]
            and template.get("issuer_did") == flow["issuer_did"]
            and template.get("status") == "ACTIVE",
            "Private Flow credential template issuer is stale")
    return {
        "schema": "marty.passport-beta-rust-owner-flow-references/v1",
        "source_commit": plan["source_commit"],
        "gateway_container_id": gateway,
        "flow_container_id": flow_container,
        "flow_definition_id": flow["flow_definition_id"],
        "credential_template_id": application["credential_template_id"],
        "definition_route_request_id": definition_request_id,
        "validation_route_request_id": validation_request_id,
        "template_route_request_id": template_request_id,
        "verified": True,
    }


def persisted_rows(plan: dict[str, Any], flow: dict[str, str],
                   application: dict[str, str],
                   instance_id: str, job_id: str, application_id: str,
                   runner: Callable[[list[str]], str]) -> None:
    instance_id = checked_uuid(instance_id)
    job_id = checked_uuid(job_id)
    application_id = checked_uuid(application_id)
    instance_sql = (
        "SELECT status FROM flow_service.flow_instances WHERE "
        f"id='{instance_id}' AND organization_id='{flow['organization_id']}' "
        f"AND flow_definition_id='{flow['flow_definition_id']}'"
    )
    job_sql = (
        "SELECT application_id || '|' || status || '|' || "
        "application_template_id || '|' || credential_template_id || '|' || "
        "delivery_destination_profile_id || '|' || coalesce(issuer_did, '') FROM "
        "issuance_service.physical_document_jobs WHERE "
        f"id='{job_id}' AND organization_id='{flow['organization_id']}' "
        f"AND flow_execution_id='{instance_id}' "
        "AND secure_artifact_ciphertext IS NOT NULL "
        "AND length(secure_artifact_ciphertext)>0"
    )
    require(beta_psql(instance_sql, runner, plan["postgres_container_id"]).lower()
            == "in_progress", "Private Flow instance did not persist")
    require(beta_psql(job_sql, runner, plan["postgres_container_id"])
            == (f"{application_id}|DRAFT|"
                f"{application['application_template_id']}|"
                f"{application['credential_template_id']}|"
                f"{application['delivery_destination_profile_id']}|"
                f"{application['issuer_did']}"),
            "Private Flow native job references differ from validated input")


def probe(plan: dict[str, Any], flow: dict[str, str], flow_sha256: str,
          application: dict[str, str], application_sha256: str,
          session: str, reference: str, *, allow_post: bool,
          expected_transition_txid: str,
          runner: Callable[[list[str]], str] = run,
          request: Callable[[str, str, str, str, dict[str, Any] | None],
                            tuple[int, dict[str, Any], str]] = private_gateway_request,
          owner_verifier: Callable[..., dict[str, Any]] = verify_rust_owner,
          existing: dict[str, Any] | None = None,
          dispatch_marker: dict[str, Any] | None = None,
          before_post: Callable[[dict[str, Any]], None] | None = None,
          ) -> dict[str, Any]:
    require(isinstance(flow_sha256, str) and DIGEST.fullmatch(flow_sha256) is not None
            and isinstance(application_sha256, str)
            and DIGEST.fullmatch(application_sha256) is not None
            and isinstance(reference, str) and REFERENCE.fullmatch(reference) is not None,
            "Private Flow input or intent digest is invalid")
    require(flow["organization_id"] == application.get("organization_id")
            and flow["issuer_did"] == application.get("issuer_did"),
            "Private Flow and application tenant or issuer differ")
    owner = owner_verifier(plan, runner=runner)
    require(owner.get("verified") is True
            and owner.get("source_commit") == plan.get("source_commit")
            and str(owner.get("transition_txid")) == expected_transition_txid
            and re.fullmatch(r"[0-9]+", expected_transition_txid) is not None,
            "Private Flow Rust owner changed")
    gateway = signed_service(plan, "gateway", runner)
    flow_container = signed_service(plan, "flow", runner)
    expected_marker = {
        "schema": "marty.passport-beta-rust-owner-flow-dispatch/v1",
        "source_commit": plan["source_commit"],
        "transition_txid": expected_transition_txid,
        "flow_file_sha256": flow_sha256,
        "application_file_sha256": application_sha256,
        "external_reference": reference,
        "gateway_container_id": gateway,
        "flow_container_id": flow_container,
    }
    require(dispatch_marker is None or dispatch_marker == expected_marker,
            "Private Flow dispatch differs from signed attempt")
    instance_id = matching_instance(plan, flow, reference, runner)
    require(instance_id is None or dispatch_marker is not None,
            "Private Flow row has no dispatch marker")
    if existing is not None:
        require(existing.get("schema") == "marty.passport-beta-rust-owner-flow/v1"
                and existing.get("source_commit") == plan.get("source_commit")
                and existing.get("transition_txid") == owner.get("transition_txid")
                and existing.get("flow_file_sha256") == flow_sha256
                and existing.get("application_file_sha256") == application_sha256
                and existing.get("external_reference") == reference
                and existing.get("gateway_container_id") == gateway
                and existing.get("flow_container_id") == flow_container
                and existing.get("flow_instance_id") == instance_id
                and isinstance(existing.get("gateway_write_route_request_id"), str),
                "Private Flow receipt differs from current generation")
        write_route_request_id = checked_uuid(
            existing["gateway_write_route_request_id"])
    elif instance_id is None:
        require(allow_post and dispatch_marker is None and before_post is not None,
                "Earlier private Flow request has no resolved database row")
        before_post(expected_marker)
        body = {"organization_id": flow["organization_id"],
                "flow_definition_id": flow["flow_definition_id"],
                "external_reference": reference,
                "subject_type": "applicant",
                "initial_context": {"physical_document": SYNTHETIC_DOCUMENT}}
        status, started, post_request_id = request(
            gateway, "POST", "/v1/flows/instances", session, body)
        require(status == 200, "Private Gateway did not start physical Flow")
        instance_id = checked_uuid(started.get("id"))
        write_route_request_id = checked_uuid(post_request_id)
    else:
        raise HostProbeError(
            "Private Flow write route response is missing; inspect the dispatch trace")
    require(instance_id is not None, "Private Flow instance is missing")
    status, current, route_request_id = request(
        gateway, "GET", f"/v1/flows/instances/{instance_id}", session, None)
    context = current.get("context_data")
    job = context.get("physical_document_job") if isinstance(context, dict) else None
    require(status == 200 and current.get("id") == instance_id
            and current.get("organization_id") == flow["organization_id"]
            and current.get("flow_id") == flow["flow_definition_id"]
            and current.get("flow_type") == "physical_document_issuance"
            and current.get("status") == "IN_PROGRESS"
            and current.get("current_step") == "accept_application"
            and isinstance(current.get("metadata"), dict)
            and current["metadata"].get("external_reference") == reference
            and isinstance(job, dict)
            and job.get("flow_execution_id") == instance_id
            and job.get("organization_id") == flow["organization_id"]
            and job.get("issuer_did") == flow["issuer_did"],
            "Private Gateway Flow or native job binding changed")
    job_id = checked_uuid(job.get("id"))
    application_id = checked_uuid(job.get("application_id"))
    require(context.get("application_id") == application_id,
            "Private Flow application context changed")
    persisted_rows(plan, flow, application, instance_id, job_id, application_id, runner)
    refreshed = owner_verifier(plan, runner=runner)
    require(refreshed == owner, "Rust owner changed during private Flow proof")
    result = {
        "schema": "marty.passport-beta-rust-owner-flow/v1",
        "source_commit": plan["source_commit"],
        "transition_txid": expected_transition_txid,
        "flow_file_sha256": flow_sha256,
        "application_file_sha256": application_sha256,
        "external_reference": reference,
        "gateway_container_id": gateway,
        "flow_container_id": flow_container,
        "gateway_write_route_request_id": write_route_request_id,
        "gateway_route_request_id": route_request_id,
        "gateway_route": "/v1/flows/instances/{flow_instance_id}",
        "flow_instance_id": instance_id,
        "job_id": job_id,
        "application_id": application_id,
        "flow_and_job_rows_verified": True,
    }
    if existing is not None:
        require(all(existing.get(key) == value for key, value in result.items()
                    if key != "gateway_route_request_id"),
                "Private Flow receipt changed")
        return existing
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--flow-file", required=True, type=Path)
    parser.add_argument("--application-file", required=True, type=Path)
    parser.add_argument("--session-file", required=True, type=Path)
    parser.add_argument("--intent", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        flow, digest = checked_flow(args.flow_file)
        application, application_digest = checked_application(args.application_file)
        session = checked_session(args.session_file)
        require(isinstance(plan, dict), "Private Flow plan is invalid")
        if args.validate_only:
            require(args.intent is None and args.receipt is None,
                    "Private Flow validation arguments are invalid")
            result = validate_live_references(plan, flow, application, session)
            result["flow_file_sha256"] = digest
            result["application_file_sha256"] = application_digest
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return
        require(args.intent is not None,
                "Private Flow write arguments are invalid")
        intent = json.loads(args.intent.read_text(encoding="utf-8"))
        require(isinstance(intent, dict)
                and intent.get("schema") == "marty.passport-beta-rust-owner-flow-intent/v1"
                and intent.get("source_commit") == plan.get("source_commit")
                and intent.get("flow_file_sha256") == digest
                and intent.get("application_file_sha256") == application_digest,
                "Private Flow intent differs from input")
        existing = (json.loads(args.receipt.read_text(encoding="utf-8"))
                    if args.receipt and args.receipt.exists() else None)
        require(existing is None or isinstance(existing, dict),
                "Private Flow receipt is invalid")
        marker_path = Path(str(args.intent) + ".dispatch.json")
        dispatch_marker = (json.loads(marker_path.read_text(encoding="utf-8"))
                           if marker_path.exists() else None)
        require(dispatch_marker is None or isinstance(dispatch_marker, dict),
                "Private Flow dispatch marker is invalid")
        result = probe(plan, flow, digest, application, application_digest, session,
                       intent.get("external_reference"),
                       allow_post=dispatch_marker is None,
                       expected_transition_txid=str(intent.get("transition_txid")),
                       existing=existing, dispatch_marker=dispatch_marker,
                       before_post=lambda marker: durable_dispatch_marker(marker_path, marker))
        require(intent.get("transition_txid") == result["transition_txid"],
                "Private Flow intent transition changed")
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Private Rust Flow proof failed: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
