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
from typing import Any, Callable
from uuid import UUID, uuid4


CONTRACT = "contracts/passport-beta-batch-acceptance.json"
CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SERVICES_IMAGE = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z")
MAX_RESPONSE_BYTES = 64 * 1024
STATUS_ORDER = {status: index for index, status in enumerate(
    ("QUEUED", "PRINTING", "ENCODING", "QUALITY_CHECK", "SHIPPED")
)}


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


def _commit(key: bytes, field: str, value: bytes) -> str:
    _require(len(key) == 32 and field in {"source_job", "bureau_job", "request", "response"},
             "Private commitment input is invalid")
    return hmac.new(key, b"passport-retirement/v2:" + field.encode("ascii") + b"\0" + value,
                    hashlib.sha256).hexdigest()


def _synthetic_job(job_id: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "application_id": "synthetic-" + job_id,
        "country_code": "USA",
        "document_type": "TD3",
        "data_groups": {"DG1": "c3ludGhldGljLWRhdGEtZ3JvdXA="},
        "sod_der_base64": "c3ludGhldGljLXNvZA==",
        "dsc_cert_pem": "synthetic-public-certificate",
        "mrz": {"line_1": "P<USASYNTHETIC<<TEST<<<<<<<<<<<<<<<<<<<<<<<<",
                "line_2": "0000000000USA0000000<<<<<<<<<<<<<<<<<<<<<<<<"},
    }


def exercise(
    organization_id: str,
    container_id: str,
    source_commit: str,
    stack_manifest_sha256: str,
    services_oci_reference: str,
    *,
    runner: Callable[[list[str], bytes], bytes] = _run_docker,
    commitment_key: bytes | None = None,
    new_uuid: Callable[[], UUID] = uuid4,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    _require(isinstance(organization_id, str) and 0 < len(organization_id) <= 256,
             "Beta organization identity is invalid")
    _require(CONTAINER_ID.fullmatch(container_id) is not None, "Beta simulator container identity is invalid")
    _require(SOURCE_COMMIT.fullmatch(source_commit) is not None
             and SHA256.fullmatch(stack_manifest_sha256) is not None
             and SERVICES_IMAGE.fullmatch(services_oci_reference) is not None,
             "Signed beta source or services image identity is invalid")
    key = secrets.token_bytes(32) if commitment_key is None else commitment_key
    _require(isinstance(key, bytes) and len(key) == 32, "Private commitment key is invalid")
    batch_id, first_id, second_id = (str(new_uuid()) for _ in range(3))
    _require(len({batch_id, first_id, second_id}) == 3, "Synthetic job IDs are not distinct")
    source_jobs = (first_id, second_id)
    request_body = json.dumps({
        "batch_id": batch_id,
        "organization_id": organization_id,
        "jobs": [_synthetic_job(job_id) for job_id in source_jobs],
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
        "request_commitment": _commit(key, "request", request_body),
        "response_commitment": _commit(key, "response", response_body),
        "submitted_job_commitments": [
            _commit(key, "source_job", job_id.encode("utf-8")) for job_id in source_jobs
        ],
        "returned_jobs": [
            {"source_job_commitment": _commit(key, "source_job", source_job.encode("utf-8")),
             "bureau_job_commitment": _commit(key, "bureau_job", mapping[source_job].encode("utf-8")),
             "status": "SHIPPED"}
            for source_job in source_jobs
        ],
        "callback_receipt_sha256": receipts[0],
        "callback_receipts_sha256": receipts,
    }
    return {"verified": True, "evidence": evidence}
