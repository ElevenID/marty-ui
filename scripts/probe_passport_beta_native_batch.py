#!/usr/bin/env python3
"""Bind one paused beta Flow job and one companion through native Rust batch."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

if __package__:
    from .probe_passport_beta_batch import CONTAINER_ID, SHA256, STATUS_ORDER, _job_commit
    from .probe_passport_beta_batch import _request as simulator_request
    from .probe_passport_beta_gateway import request_beta
else:
    from probe_passport_beta_batch import CONTAINER_ID, SHA256, STATUS_ORDER, _job_commit
    from probe_passport_beta_batch import _request as simulator_request
    from probe_passport_beta_gateway import request_beta


IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,255}\Z")
MAX_RESPONSE_BYTES = 64 * 1024


class NativeBatchProbeError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeBatchProbeError(message)


def _canonical_uuid(value: Any) -> str:
    try:
        parsed = str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise NativeBatchProbeError("Native batch bureau identity is invalid") from exc
    _require(value == parsed, "Native batch bureau identity is not canonical")
    return parsed


def ensure_private_state_available(path: Path) -> None:
    _require(isinstance(path, Path) and path.is_absolute()
             and Path.cwd().resolve() not in path.resolve().parents
             and not path.is_symlink(),
             "Protected native batch state path is invalid")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        _require(path.parent.stat().st_mode & 0o077 == 0,
                 "Protected native batch state directory is not private")
    _require(not path.exists(),
             "Pending native batch requires protected reconciliation before another run")


def _sync_private_directory(path: Path) -> None:
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _write_private_state(path: Path, record: dict[str, Any], *, initial: bool) -> None:
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    target = path if initial else path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        if not initial:
            _require(path.exists(), "Protected native batch state disappeared")
            os.replace(target, path)
        _sync_private_directory(path)
    except (OSError, ValueError) as exc:
        raise NativeBatchProbeError("Protected native batch state could not be retained") from exc
    finally:
        if not initial and target.exists():
            target.unlink()


def clear_private_state(path: Path) -> None:
    try:
        path.unlink()
        _sync_private_directory(path)
    except OSError as exc:
        raise NativeBatchProbeError("Completed native batch state could not be cleared") from exc


def write_private_demo_handoff(path: Path, record: dict[str, str]) -> None:
    required = {"schema", "source_commit", "stack_manifest_sha256", "organization_id",
                "flow_definition_id", "flow_instance_id", "application_id",
                "source_job_id", "bureau_job_id"}
    _require(isinstance(record, dict) and set(record) == required
             and record.get("schema") == "marty.passport-beta-demo-private/v1"
             and all(isinstance(record.get(key), str) and bool(record[key])
                     for key in required)
             and re.fullmatch(r"[0-9a-f]{40}", record["source_commit"]) is not None
             and SHA256.fullmatch(record["stack_manifest_sha256"]) is not None
             and all(IDENTIFIER.fullmatch(record[key]) is not None for key in (
                 "organization_id", "flow_definition_id", "flow_instance_id",
                 "application_id", "source_job_id")),
             "Protected demo handoff is incomplete")
    _canonical_uuid(record["bureau_job_id"])
    ensure_private_state_available(path)
    _write_private_state(path, record, initial=True)


def _curl_value(value: str) -> str:
    _require("\r" not in value and "\n" not in value and "\0" not in value,
             "Native batch private request contains invalid control characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _run_docker(command: list[str], config: bytes) -> bytes:
    try:
        result = subprocess.run(command, input=config, capture_output=True,
                                check=False, timeout=70)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NativeBatchProbeError("Private native batch request failed") from exc
    if result.returncode != 0:
        raise NativeBatchProbeError("Private native batch request failed")
    return result.stdout


def _request_private(
    container_id: str,
    method: str,
    path: str,
    body: dict[str, str] | None,
    organization_id: str,
    service_token: str,
    operator_token: str,
    wire_key: bytes | None,
    runner: Callable[[list[str], bytes], bytes],
) -> tuple[int, dict[str, Any]]:
    _require(CONTAINER_ID.fullmatch(container_id) is not None
             and isinstance(organization_id, str) and IDENTIFIER.fullmatch(organization_id)
             and isinstance(service_token, str) and len(service_token) >= 32
             and isinstance(operator_token, str) and len(operator_token) >= 32
             and service_token != operator_token,
             "Private native batch credentials are incomplete")
    url = "http://127.0.0.1:8005" + path
    # curl reads the whole private configuration from stdin. Neither tenant
    # credential nor run key appears in Docker/curl argv or public output.
    lines = [
        "silent", "show-error", "max-time = 60", "write-out = \"\\n%{http_code}\"",
        "request = " + _curl_value(method), "url = " + _curl_value(url),
        "header = " + _curl_value("Accept: application/json"),
        "header = " + _curl_value("x-organization-id: " + organization_id),
        "header = " + _curl_value("x-api-key: " + service_token),
        "header = " + _curl_value("x-passport-reconciliation-token: " + operator_token),
    ]
    if body is not None:
        _require(method == "POST" and isinstance(wire_key, bytes) and len(wire_key) == 32,
                 "Private native batch body is invalid")
        lines.extend([
            "header = " + _curl_value("Content-Type: application/json"),
            "header = " + _curl_value("x-passport-batch-wire-key: " + base64.b64encode(wire_key).decode("ascii")),
            "data-binary = " + _curl_value(json.dumps(body, separators=(",", ":"), sort_keys=True)),
        ])
    raw = runner(["docker", "exec", "-i", container_id, "curl", "--config", "-"],
                 ("\n".join(lines) + "\n").encode("utf-8"))
    _require(len(raw) <= MAX_RESPONSE_BYTES, "Private native batch response is oversized")
    try:
        response_body, status_bytes = raw.rsplit(b"\n", 1)
        status = int(status_bytes)
        response = json.loads(response_body)
    except (TypeError, ValueError) as exc:
        raise NativeBatchProbeError("Private native batch response is invalid") from exc
    _require(isinstance(response, dict), "Private native batch response is invalid")
    return status, response


def request_private_preflight(
    container_id: str,
    organization_id: str,
    service_token: str,
    operator_token: str,
    *,
    runner: Callable[[list[str], bytes], bytes] = _run_docker,
) -> None:
    status, response = _request_private(
        container_id, "GET", "/internal/passport/beta-batches/preflight", None,
        organization_id, service_token, operator_token, None, runner)
    _require(status == 200 and response == {
        "ready": True, "provider_profile_id": "passport-beta-bureau",
        "issuer_mode": "managed-issuer-profile", "artifact_custody": "kms",
    }, "Protected native batch credentials or destination are not ready")


def request_private_batch(
    container_id: str,
    batch_id: str,
    body: dict[str, str],
    organization_id: str,
    service_token: str,
    operator_token: str,
    wire_key: bytes,
    *,
    runner: Callable[[list[str], bytes], bytes] = _run_docker,
) -> tuple[int, dict[str, Any]]:
    try:
        canonical_batch_id = str(UUID(batch_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise NativeBatchProbeError("Private native batch identity is invalid") from exc
    _require(batch_id == canonical_batch_id
             and set(body) == {"selected_flow_instance_id", "selected_application_id",
                               "companion_application_id"}
             and all(isinstance(value, str) and IDENTIFIER.fullmatch(value)
                     for value in body.values()),
             "Private native batch inputs are incomplete")
    return _request_private(
        container_id, "POST", "/internal/passport/beta-batches/" + batch_id + "/submit",
        body, organization_id, service_token, operator_token, wire_key, runner)


def exercise(
    application: dict[str, Any],
    physical_document: dict[str, Any],
    api_key: str,
    service_token: str,
    operator_token: str,
    native_container_id: str,
    simulator_container_id: str,
    selected_flow_instance_id: str,
    selected_application_id: str,
    selected_source_job_id: str,
    selected_sod_sha256: str,
    dsc_der_sha256: str,
    dsc_pem_wire_sha256: str,
    material_receipt: Callable[..., dict[str, Any]],
    private_state_path: Path,
    *,
    gateway_request: Callable[..., tuple[int, dict[str, Any]]] = request_beta,
    private_request: Callable[..., tuple[int, dict[str, Any]]] = request_private_batch,
    simulator_get: Callable[..., tuple[int, bytes, dict[str, Any]]] = simulator_request,
    new_uuid: Callable[[], UUID] = uuid4,
    new_key: Callable[[int], bytes] = secrets.token_bytes,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, dict[str, Any]]:
    org = application.get("organization_id")
    issuer = application.get("issuer_did")
    _require(isinstance(org, str) and IDENTIFIER.fullmatch(org) is not None
             and isinstance(issuer, str) and issuer.startswith("did:")
             and isinstance(api_key, str) and len(api_key) >= 32
             and isinstance(service_token, str) and len(service_token) >= 32
             and isinstance(operator_token, str) and len(operator_token) >= 32
             and service_token != operator_token
             and CONTAINER_ID.fullmatch(native_container_id) is not None
             and CONTAINER_ID.fullmatch(simulator_container_id) is not None
             and all(isinstance(value, str) and IDENTIFIER.fullmatch(value)
                     for value in (selected_flow_instance_id, selected_application_id,
                                   selected_source_job_id))
             and isinstance(selected_sod_sha256, str) and SHA256.fullmatch(selected_sod_sha256)
             and isinstance(dsc_der_sha256, str) and SHA256.fullmatch(dsc_der_sha256)
             and isinstance(dsc_pem_wire_sha256, str) and SHA256.fullmatch(dsc_pem_wire_sha256)
             and isinstance(physical_document, dict),
             "Native beta batch inputs are incomplete")
    ensure_private_state_available(private_state_path)
    companion_flow_id = "passport-native-batch-" + str(new_uuid())
    batch_id = str(new_uuid())
    wire_key = new_key(32)
    _require(isinstance(wire_key, bytes) and len(wire_key) == 32,
             "Private wire key is invalid")
    private_record = {
        "schema": "marty.passport-beta-native-pending/v1",
        "organization_id": org,
        "selected_flow_instance_id": selected_flow_instance_id,
        "selected_application_id": selected_application_id,
        "selected_source_job_id": selected_source_job_id,
        "selected_sod_sha256": selected_sod_sha256,
        "companion_flow_execution_id": companion_flow_id,
        "batch_id": batch_id,
        "wire_key_b64": base64.b64encode(wire_key).decode("ascii"),
        "state": "preparing_companion",
    }
    _write_private_state(private_state_path, private_record, initial=True)
    companion_body = {**application, **physical_document, "flow_execution_id": companion_flow_id}
    code, created = gateway_request("POST", "/v1/passport/applications", companion_body, api_key)
    companion_app, companion_job = created.get("application_id"), created.get("id")
    _require(code == 201 and created.get("status") == "DRAFT"
             and created.get("organization_id") == org and created.get("issuer_did") == issuer
             and created.get("flow_execution_id") == companion_flow_id
             and isinstance(companion_app, str) and IDENTIFIER.fullmatch(companion_app)
             and isinstance(companion_job, str) and IDENTIFIER.fullmatch(companion_job)
             and companion_app != selected_application_id
             and companion_job != selected_source_job_id,
             "Native companion creation did not produce a distinct managed job")
    private_record.update(companion_application_id=companion_app,
                          companion_source_job_id=companion_job,
                          state="preparing_signed_material")
    _write_private_state(private_state_path, private_record, initial=False)
    base = "/v1/passport/applications/" + quote(companion_app, safe="")
    for suffix, expected in (("generate-data-groups", "DATA_GENERATED"),
                             ("generate-sod", "SOD_SIGNED")):
        code, prepared = gateway_request("POST", base + "/" + suffix, None, api_key)
        _require(code == 200 and prepared.get("id") == companion_job
                 and prepared.get("application_id") == companion_app
                 and prepared.get("organization_id") == org
                 and prepared.get("issuer_did") == issuer
                 and prepared.get("flow_execution_id") == companion_flow_id
                 and prepared.get("status") == expected,
                 "Native companion preparation changed identity")
        if suffix == "generate-sod":
            companion_sod = prepared.get("sod_sha256")
            _require(prepared.get("sod_signature_verified") is True
                     and isinstance(companion_sod, str) and SHA256.fullmatch(companion_sod),
                     "Native companion SOD is unverified")
    private_record["state"] = "dispatching"
    _write_private_state(private_state_path, private_record, initial=False)
    body = {"selected_flow_instance_id": selected_flow_instance_id,
            "selected_application_id": selected_application_id,
            "companion_application_id": companion_app}
    mapping = None
    commitments = None
    try:
        code, result = private_request(native_container_id, batch_id, body, org,
                                       service_token, operator_token, wire_key)
    except NativeBatchProbeError:
        # A lost response is ambiguous. The native lease permits one exact
        # retry; it will still withhold first-dispatch proof if that was lost.
        sleep(131)
        code, result = private_request(native_container_id, batch_id, body, org,
                                       service_token, operator_token, wire_key)
    else:
        if code in (409, 502, 503, 504):
            sleep(131)
            code, result = private_request(native_container_id, batch_id, body, org,
                                           service_token, operator_token, wire_key)
    for attempt in range(2):
        if attempt:
            code, result = private_request(native_container_id, batch_id, body, org,
                                           service_token, operator_token, wire_key)
        jobs = result.get("jobs")
        proof = result.get("wire_commitments")
        _require(code == 200 and result.get("batch_id") == batch_id
                 and result.get("wire_evidence_status") == "verified"
                 and result.get("http_status") == 202
                 and result.get("batch_status") == "QUEUED"
                 and isinstance(proof, dict)
                 and all(isinstance(proof.get(field), str) and SHA256.fullmatch(proof[field])
                         for field in ("request_commitment", "response_commitment"))
                 and isinstance(jobs, list) and len(jobs) == 2,
                 "Native batch did not return verified first-dispatch proof")
        observed = {}
        for job in jobs:
            _require(isinstance(job, dict) and job.get("organization_id") == org
                     and isinstance(job.get("id"), str)
                     and isinstance(job.get("application_id"), str)
                     and job.get("issuer_did") == issuer
                     and job.get("status") in ("SUBMITTED", "IN_PRODUCTION", "QUALITY_CHECK",
                                               "READY_FOR_ACTIVATION", "ACTIVE"),
                     "Native batch returned an invalid bound job")
            observed[job["id"]] = job
        _require(set(observed) == {selected_source_job_id, companion_job}
                 and observed[selected_source_job_id]["application_id"] == selected_application_id
                 and observed[selected_source_job_id]["flow_execution_id"] == selected_flow_instance_id
                 and observed[companion_job]["application_id"] == companion_app
                 and observed[companion_job]["flow_execution_id"] == companion_flow_id,
                 "Native batch did not bind the exact selected and companion jobs")
        current_mapping = {source: _canonical_uuid(job.get("bureau_job_id"))
                           for source, job in observed.items()}
        _require(len(set(current_mapping.values())) == 2,
                 "Native batch returned duplicate bureau jobs")
        if attempt:
            _require(current_mapping == mapping and proof == commitments,
                     "Native batch retry changed first-dispatch proof or bindings")
        mapping, commitments = current_mapping, proof
    receipts = {}
    for source, sod in ((selected_source_job_id, selected_sod_sha256),
                        (companion_job, companion_sod)):
        receipt = material_receipt(org, source, mapping[source], sod,
                                   dsc_der_sha256, dsc_pem_wire_sha256,
                                   api_key.encode("utf-8"))
        evidence = receipt.get("evidence") if isinstance(receipt, dict) else None
        _require(isinstance(receipt, dict) and receipt.get("verified") is True
                 and isinstance(evidence, dict)
                 and evidence.get("tenant_and_job_binding") is True
                 and evidence.get("first_accepted_sod_der_matches_native") is True
                 and evidence.get("first_accepted_dsc_der_matches_selected_chain") is True
                 and evidence.get("first_accepted_dsc_pem_wire_matches_selected_chain") is True
                 and evidence.get("source_job_id_commitment") == _job_commit(api_key, "source-job", source)
                 and evidence.get("bureau_job_id_commitment") == _job_commit(api_key, "bureau-job", mapping[source]),
                 "Native batch first-accepted material receipt is unverified")
        receipts[source] = evidence
    companion_bureau = mapping[companion_job]
    code, bound = gateway_request("POST", base + "/submit-personalization", None, api_key)
    _require(code == 200 and bound.get("id") == companion_job
             and bound.get("application_id") == companion_app
             and bound.get("bureau_job_id") == companion_bureau,
             "Companion single submit changed native batch binding")
    deadline = now() + 120
    prior_order = -1
    companion_callback = None
    while now() < deadline:
        code, _, observed = simulator_get(simulator_container_id, "GET",
                                          "/v1/personalization/jobs/" + companion_bureau)
        state = observed.get("status")
        _require(code == 200 and state in STATUS_ORDER and STATUS_ORDER[state] >= prior_order,
                 "Companion simulator status regressed")
        prior_order = STATUS_ORDER[state]
        if state == "SHIPPED":
            companion_callback = observed.get("callback_receipt_sha256")
            _require(observed.get("tracking_number") == "BETA-SIM-" + UUID(companion_bureau).hex
                     and isinstance(companion_callback, str) and SHA256.fullmatch(companion_callback),
                     "Companion signed callback receipt is missing")
            break
        sleep(2)
    else:
        raise NativeBatchProbeError("Companion simulator callback did not complete")
    while now() < deadline:
        code, production = gateway_request("GET", base + "/production-status", None, api_key)
        _require(code == 200 and production.get("id") == companion_job
                 and production.get("organization_id") == org
                 and production.get("application_id") == companion_app
                 and production.get("flow_execution_id") == companion_flow_id
                 and production.get("bureau_job_id") == companion_bureau,
                 "Companion callback changed native job identity")
        if production.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"):
            break
        _require(production.get("status") not in ("FAILED", "CANCELLED", "ACTIVE"),
                 "Companion callback reached an invalid native state")
        sleep(2)
    else:
        raise NativeBatchProbeError("Companion callback did not reach native production")
    code, quality = gateway_request("POST", base + "/quality-verify",
                                    {"passed": True, "failure_codes": []}, api_key)
    _require(code == 200 and quality.get("id") == companion_job
             and quality.get("bureau_job_id") == companion_bureau
             and quality.get("status") == "READY_FOR_ACTIVATION",
             "Companion quality result did not persist")
    code, active = gateway_request("POST", base + "/activate", None, api_key)
    _require(code == 200 and active.get("id") == companion_job
             and active.get("bureau_job_id") == companion_bureau
             and active.get("status") == "ACTIVE" and bool(active.get("completed_at")),
             "Companion activation did not persist")
    return mapping[selected_source_job_id], {
        "verified": True,
        "evidence": {
            "provider_kind": "simulator", "physical_claim": "not_claimed",
            "http_status": 202, "batch_status": "QUEUED",
            "selected_flow_in_two_job_batch": True,
            "native_binding_verified": True,
            "first_accepted_material_verified": True,
            "selected_material_receipt": receipts[selected_source_job_id],
            "companion_native_completed": True,
            "companion_callback_receipt_sha256": companion_callback,
            "selected_source_job_commitment": receipts[selected_source_job_id]["source_job_id_commitment"],
            "selected_bureau_job_commitment": receipts[selected_source_job_id]["bureau_job_id_commitment"],
            "companion_source_job_commitment": receipts[companion_job]["source_job_id_commitment"],
            "companion_bureau_job_commitment": receipts[companion_job]["bureau_job_id_commitment"],
            "submitted_job_commitments": [
                receipts[selected_source_job_id]["source_job_id_commitment"],
                receipts[companion_job]["source_job_id_commitment"],
            ],
            "returned_jobs": [
                {"source_job_commitment": receipts[selected_source_job_id]["source_job_id_commitment"],
                 "bureau_job_commitment": receipts[selected_source_job_id]["bureau_job_id_commitment"]},
                {"source_job_commitment": receipts[companion_job]["source_job_id_commitment"],
                 "bureau_job_commitment": receipts[companion_job]["bureau_job_id_commitment"]},
            ],
            "request_commitment": commitments["request_commitment"],
            "response_commitment": commitments["response_commitment"],
        },
    }
