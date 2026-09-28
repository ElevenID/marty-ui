#!/usr/bin/env python3
"""Probe the private beta simulator batch and publish only keyed commitments."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import subprocess
import time
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

if __package__:
    from .probe_passport_beta_gateway import request_beta as request_native
else:
    from probe_passport_beta_gateway import request_beta as request_native


CONTRACT = "contracts/passport-beta-batch-acceptance.json"
CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SERVICES_IMAGE = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z")
NATIVE_ID = re.compile(r"[A-Za-z0-9_-]{1,255}\Z")
MAX_RESPONSE_BYTES = 64 * 1024
STATUS_ORDER = {status: index for index, status in enumerate(
    ("QUEUED", "PRINTING", "ENCODING", "QUALITY_CHECK", "SHIPPED")
)}
SYNTHETIC_DOCUMENT = {
    "country_code": "USA",
    "document_type": "TD3",
    "applicant": {"name": "Synthetic Test"},
    "mrz": {"line_1": "P<USASYNTHETIC<<TEST<<<<<<<<<<<<<<<<<<<<<<<<",
            "line_2": "0000000000USA0000000<<<<<<<<<<<<<<<<<<<<<<<<"},
    "data_groups": {"DG1": "c3ludGhldGljLWRhdGEtZ3JvdXA=",
                    "DG2": "c3ludGhldGljLXR3bw=="},
}


class BatchProbeError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BatchProbeError(message)


def _run_docker(command: list[str], body: bytes) -> bytes:
    try:
        result = subprocess.run(command, input=body, capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BatchProbeError("Private beta simulator request failed") from exc
    if result.returncode != 0:
        raise BatchProbeError("Private beta simulator request failed")
    return result.stdout


def _request(
    container_id: str,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    runner: Callable[[list[str], bytes], bytes] = _run_docker,
) -> tuple[int, bytes, dict[str, Any]]:
    _require(CONTAINER_ID.fullmatch(container_id) is not None, "Beta simulator container identity is invalid")
    _require(method in ("GET", "POST"), "Unexpected simulator method")
    _require(path == "/v1/personalization/batches" or re.fullmatch(
        r"/v1/personalization/jobs/[0-9a-f-]{36}", path
    ) is not None, "Unexpected simulator route")
    url = "http://127.0.0.1:8020" + path
    script = (
        'test -n "$GRPC_SERVICE_TOKEN"; '
        'curl --silent --show-error --max-time 20 --write-out "\\n%{http_code}" '
        '--header "Authorization: Bearer $GRPC_SERVICE_TOKEN" '
        '--header "Content-Type: application/json" '
        + ('--data-binary @- ' if method == "POST" else '--request GET ')
        + '--url "$1"'
    )
    command = ["docker", "exec", "-i", container_id, "sh", "-ec", script, "batch-probe", url]
    response = runner(command, body)
    _require(len(response) <= MAX_RESPONSE_BYTES, "Private simulator response is oversized")
    try:
        raw_body, status_bytes = response.rsplit(b"\n", 1)
        status = int(status_bytes)
        payload = json.loads(raw_body)
    except (ValueError, TypeError) as exc:
        raise BatchProbeError("Private simulator response is invalid") from exc
    _require(isinstance(payload, dict), "Private simulator response is invalid")
    return status, raw_body, payload


def _wire_commit(key: bytes, field: str, value: bytes) -> str:
    _require(len(key) == 32 and field in {"request", "response"},
             "Private wire commitment input is invalid")
    return hmac.new(key, b"passport-retirement/v2:" + field.encode("ascii") + b"\0" + value,
                    hashlib.sha256).hexdigest()


def _job_commit(api_key: str, field: str, job_id: str) -> str:
    _require(field in {"source-job", "bureau-job"} and isinstance(job_id, str) and job_id,
             "Private job commitment input is invalid")
    return hmac.new(api_key.encode("utf-8"), (field + ":" + job_id).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _synthetic_job(job_id: str, application_id: str, application: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "application_id": application_id,
        "country_code": application["country_code"],
        "document_type": application.get("document_type", "TD3"),
        "data_groups": application["data_groups"],
        "sod_der_base64": "c3ludGhldGljLXNvZA==",
        "dsc_cert_pem": "synthetic-public-certificate",
        "mrz": {"line_1": application["mrz"]["line_1"],
                "line_2": application["mrz"]["line_2"]},
    }


def exercise(
    application: dict[str, Any],
    api_key: str,
    container_id: str,
    source_commit: str,
    stack_manifest_sha256: str,
    services_oci_reference: str,
    *,
    runner: Callable[[list[str], bytes], bytes] = _run_docker,
    native_request: Callable[[str, str, dict[str, Any] | None, str], tuple[int, dict[str, Any]]] = request_native,
    commitment_key: bytes | None = None,
    new_uuid: Callable[[], UUID] = uuid4,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    _require(isinstance(application, dict), "Beta application is invalid")
    organization_id = application.get("organization_id")
    _require(isinstance(organization_id, str) and 0 < len(organization_id) <= 256
             and isinstance(application.get("issuer_did"), str)
             and application["issuer_did"].startswith("did:")
             and isinstance(api_key, str) and len(api_key) >= 32,
             "Beta managed application identity is invalid")
    for name in ("application_template_id", "credential_template_id",
                 "delivery_destination_profile_id"):
        _require(isinstance(application.get(name), str) and application[name],
                 "Beta batch application profile is invalid")
    batch_application = {
        "organization_id": organization_id,
        "issuer_did": application["issuer_did"],
        "application_template_id": application["application_template_id"],
        "credential_template_id": application["credential_template_id"],
        "delivery_destination_profile_id": application["delivery_destination_profile_id"],
        **SYNTHETIC_DOCUMENT,
    }
    _require(CONTAINER_ID.fullmatch(container_id) is not None, "Beta simulator container identity is invalid")
    _require(SOURCE_COMMIT.fullmatch(source_commit) is not None
             and SHA256.fullmatch(stack_manifest_sha256) is not None
             and SERVICES_IMAGE.fullmatch(services_oci_reference) is not None,
             "Signed beta source or services image identity is invalid")
    key = secrets.token_bytes(32) if commitment_key is None else commitment_key
    _require(isinstance(key, bytes) and len(key) == 32, "Private commitment key is invalid")
    batch_id, first_run, second_run = (str(new_uuid()) for _ in range(3))
    _require(len({batch_id, first_run, second_run}) == 3, "Synthetic run IDs are not distinct")
    native_jobs: dict[str, str] = {}
    native_flows: dict[str, str] = {}
    for run_id in (first_run, second_run):
        body = {**batch_application, "flow_execution_id": "passport-batch-" + run_id}
        status, created = native_request("POST", "/v1/passport/applications", body, api_key)
        job_id, application_id = created.get("id"), created.get("application_id")
        _require(status == 201 and created.get("organization_id") == organization_id
                 and created.get("status") == "DRAFT"
                 and created.get("flow_execution_id") == body["flow_execution_id"]
                 and isinstance(job_id, str) and NATIVE_ID.fullmatch(job_id) is not None
                 and isinstance(application_id, str)
                 and NATIVE_ID.fullmatch(application_id) is not None
                 and job_id not in native_jobs,
                 "Native beta batch job creation failed")
        base = "/v1/passport/applications/" + application_id
        for suffix, expected in (("generate-data-groups", "DATA_GENERATED"),
                                 ("generate-sod", "SOD_SIGNED")):
            step_status, result = native_request("POST", base + "/" + suffix, None, api_key)
            _require(step_status == 200 and result.get("organization_id") == organization_id
                     and result.get("id") == job_id
                     and result.get("application_id") == application_id
                     and result.get("flow_execution_id") == body["flow_execution_id"]
                     and result.get("status") == expected,
                     "Native beta batch preparation drifted")
            if suffix == "generate-sod":
                _require(result.get("sod_signature_verified") is True
                         and isinstance(result.get("sod_sha256"), str)
                         and SHA256.fullmatch(result["sod_sha256"]) is not None,
                         "Native beta batch managed SOD is unverified")
        native_jobs[job_id] = application_id
        native_flows[job_id] = body["flow_execution_id"]
    source_jobs = tuple(native_jobs)
    request_body = json.dumps({
        "batch_id": batch_id,
        "organization_id": organization_id,
        "jobs": [_synthetic_job(job_id, native_jobs[job_id], batch_application)
                 for job_id in source_jobs],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    status, response_body, response = _request(
        container_id, "POST", "/v1/personalization/batches", request_body, runner=runner,
    )
    _require(status == 202 and response.get("status") == "QUEUED",
             "Beta simulator did not accept the synthetic batch")
    returned = response.get("jobs")
    _require(isinstance(returned, list) and len(returned) == len(source_jobs),
             "Beta simulator returned an incomplete batch")
    mapping: dict[str, str] = {}
    for item in returned:
        _require(isinstance(item, dict) and item.get("status") == "QUEUED"
                 and isinstance(item.get("job_id"), str)
                 and isinstance(item.get("bureau_job_id"), str),
                 "Beta simulator job mapping is invalid")
        try:
            bureau_id = str(UUID(item["bureau_job_id"]))
        except ValueError as exc:
            raise BatchProbeError("Beta simulator bureau identity is invalid") from exc
        _require(item["bureau_job_id"] == bureau_id,
                 "Beta simulator bureau identity is not canonical")
        _require(item["job_id"] in source_jobs and item["job_id"] not in mapping,
                 "Beta simulator job mapping is not one-to-one")
        mapping[item["job_id"]] = bureau_id
    _require(set(mapping) == set(source_jobs) and len(set(mapping.values())) == len(source_jobs),
             "Beta simulator job mapping is not one-to-one")
    for source_job in source_jobs:
        base = "/v1/passport/applications/" + native_jobs[source_job]
        native_status, bound = native_request("POST", base + "/submit-personalization", None, api_key)
        _require(native_status == 200 and bound.get("organization_id") == organization_id
                 and bound.get("id") == source_job
                 and bound.get("application_id") == native_jobs[source_job]
                 and bound.get("flow_execution_id") == native_flows[source_job]
                 and bound.get("bureau_job_id") == mapping[source_job]
                 and bound.get("status") in ("SUBMITTED", "IN_PRODUCTION", "QUALITY_CHECK",
                                               "READY_FOR_ACTIVATION"),
                 "Native beta batch bureau binding did not match the private batch")
    receipts: list[str] = []
    deadline = now() + 120
    for source_job in source_jobs:
        bureau_id = mapping[source_job]
        prior_order = -1
        while now() < deadline:
            poll_status, _, observed = _request(
                container_id, "GET", f"/v1/personalization/jobs/{bureau_id}", runner=runner,
            )
            state = observed.get("status")
            _require(poll_status == 200 and state in STATUS_ORDER
                     and STATUS_ORDER[state] >= prior_order,
                     "Beta simulator status regressed or poll failed")
            prior_order = STATUS_ORDER[state]
            if state == "SHIPPED":
                _require(observed.get("tracking_number") == f"BETA-SIM-{UUID(bureau_id).hex}"
                         and isinstance(observed.get("callback_receipt_sha256"), str)
                         and SHA256.fullmatch(observed["callback_receipt_sha256"]) is not None,
                         "Beta simulator signed callback receipt is missing")
                receipts.append(observed["callback_receipt_sha256"])
                break
            sleep(2)
        else:
            raise BatchProbeError("Beta simulator callback did not complete within the bound")
        base = "/v1/passport/applications/" + native_jobs[source_job]
        native_status, production = native_request("GET", base + "/production-status", None, api_key)
        _require(native_status == 200 and production.get("organization_id") == organization_id
                 and production.get("id") == source_job
                 and production.get("application_id") == native_jobs[source_job]
                 and production.get("flow_execution_id") == native_flows[source_job]
                 and production.get("bureau_job_id") == bureau_id
                 and production.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"),
                 "Native beta batch callback did not reach the same job")
        quality_status, quality = native_request("POST", base + "/quality-verify",
                                                 {"passed": True, "failure_codes": []}, api_key)
        _require(quality_status == 200 and quality.get("organization_id") == organization_id
                 and quality.get("application_id") == native_jobs[source_job]
                 and quality.get("flow_execution_id") == native_flows[source_job]
                 and quality.get("id") == source_job
                 and quality.get("bureau_job_id") == bureau_id
                 and quality.get("status") == "READY_FOR_ACTIVATION",
                 "Native beta batch quality state did not persist")
        active_status, active = native_request("POST", base + "/activate", None, api_key)
        _require(active_status == 200 and active.get("organization_id") == organization_id
                 and active.get("application_id") == native_jobs[source_job]
                 and active.get("flow_execution_id") == native_flows[source_job]
                 and active.get("id") == source_job
                 and active.get("bureau_job_id") == bureau_id
                 and active.get("status") == "ACTIVE" and active.get("completed_at"),
                 "Native beta batch activation did not persist")
        final_status, final = native_request("GET", base + "/production-status", None, api_key)
        _require(final_status == 200 and final.get("organization_id") == organization_id
                 and final.get("application_id") == native_jobs[source_job]
                 and final.get("flow_execution_id") == native_flows[source_job]
                 and final.get("id") == source_job
                 and final.get("bureau_job_id") == bureau_id
                 and final.get("status") == "ACTIVE" and final.get("completed_at"),
                 "Native beta batch terminal read did not persist")
    _require(len(set(receipts)) == len(source_jobs),
             "Beta simulator signed callback receipts are not distinct")
    evidence = {
        "provider_kind": "simulator",
        "physical_claim": "not_claimed",
        "simulator_marker_verified": True,
        "commitment_scheme": "HMAC-SHA256",
        "source_commit": source_commit,
        "stack_manifest_sha256": stack_manifest_sha256,
        "services_oci_reference": services_oci_reference,
        "http_status": status,
        "batch_status": response["status"],
        "native_binding_verified": True,
        "native_completed_jobs": len(source_jobs),
        "request_commitment": _wire_commit(key, "request", request_body),
        "response_commitment": _wire_commit(key, "response", response_body),
        "submitted_job_commitments": [
            _job_commit(api_key, "source-job", job_id) for job_id in source_jobs
        ],
        "returned_jobs": [
            {"source_job_commitment": _job_commit(api_key, "source-job", source_job),
             "bureau_job_commitment": _job_commit(api_key, "bureau-job", mapping[source_job]),
             "status": "SHIPPED"}
            for source_job in source_jobs
        ],
        "callback_receipt_sha256": receipts[0],
        "callback_receipts_sha256": receipts,
    }
    return {"verified": True, "evidence": evidence}
