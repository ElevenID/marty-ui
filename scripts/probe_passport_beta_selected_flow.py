#!/usr/bin/env python3
"""Exercise one governed beta passport Flow and bind its durable native job."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

if __package__:
    from .probe_passport_beta_flow import PHYSICAL_STEPS
    from .probe_passport_beta_gateway import request_beta as request_passport
    from .probe_passport_beta_batch import (
        CONTAINER_ID, STATUS_ORDER, _request as request_simulator,
    )
else:
    from probe_passport_beta_flow import PHYSICAL_STEPS
    from probe_passport_beta_gateway import request_beta as request_passport
    from probe_passport_beta_batch import (
        CONTAINER_ID, STATUS_ORDER, _request as request_simulator,
    )


ORIGIN = "https://beta.elevenidllc.com"
IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,255}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REFERENCES = ("application_template_id", "credential_template_id",
              "delivery_destination_profile_id")


class SelectedFlowError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def request_flow(method: str, path: str, body: dict[str, Any] | None,
                 operator_cookie: str) -> tuple[int, dict[str, Any]]:
    if (not path.startswith("/v1/flows/") or ".." in path
            or not operator_cookie or any(character in operator_cookie for character in "\r\n")):
        raise SelectedFlowError("Selected Flow request is invalid")
    url = ORIGIN + path
    headers = {"Accept": "application/json", "Cache-Control": "no-cache",
               "User-Agent": "passport-beta-flow-acceptance/1", "Cookie": operator_cookie}
    encoded = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    try:
        with build_opener(ProxyHandler({}), NoRedirect).open(
            Request(url, data=encoded, headers=headers, method=method), timeout=60,
        ) as response:
            if response.geturl() != url:
                raise SelectedFlowError("Selected Flow route redirected")
            raw = response.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise SelectedFlowError("Selected Flow response is oversized")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise SelectedFlowError("Selected Flow response is invalid")
            return response.status, payload
    except HTTPError as exc:
        return exc.code, {}
    except (OSError, URLError, ValueError) as exc:
        raise SelectedFlowError("Selected Flow request failed") from exc


def validate_inputs(
    flow_definition_id: str,
    organization_id: str,
    issuer_did: str,
    references: dict[str, str],
    physical_document: dict[str, Any],
    operator_cookie: str,
    api_key: str,
    simulator_container_id: str,
    max_polls: int = 90,
    poll_interval_seconds: float = 10,
) -> None:
    if (not isinstance(flow_definition_id, str) or not IDENTIFIER.fullmatch(flow_definition_id)
            or not isinstance(organization_id, str) or not organization_id
            or not isinstance(issuer_did, str) or not issuer_did.startswith("did:")
            or not isinstance(references, dict)
            or any(not isinstance(references.get(key), str) or not references[key] for key in REFERENCES)
            or not isinstance(physical_document, dict)
            or any(not physical_document.get(key) for key in ("country_code", "applicant", "mrz", "data_groups"))
            or any(key in physical_document for key in ("issuer_did", "organization_id",
                                                   "application_template_id", "credential_template_id",
                                                   "delivery_destination_profile_id"))
            or not isinstance(operator_cookie, str) or not operator_cookie
            or any(character in operator_cookie for character in "\r\n")
            or not isinstance(api_key, str) or len(api_key) < 32
            or not isinstance(simulator_container_id, str)
            or CONTAINER_ID.fullmatch(simulator_container_id) is None
            or not 1 <= max_polls <= 180 or poll_interval_seconds < 0):
        raise SelectedFlowError("Selected Flow inputs are incomplete")


def exercise(
    flow_definition_id: str,
    organization_id: str,
    issuer_did: str,
    references: dict[str, str],
    physical_document: dict[str, Any],
    operator_cookie: str,
    api_key: str,
    *,
    simulator_container_id: str,
    on_submission: Callable[[str, str, str, str], dict[str, Any]],
    on_signed_sod: Callable[[str, str, str, str, str], str] | None = None,
    request: Callable[[str, str, dict[str, Any] | None, str], tuple[int, dict[str, Any]]] = request_flow,
    passport_request: Callable[[str, str, dict[str, Any] | None, str], tuple[int, dict[str, Any]]] = request_passport,
    simulator_request: Callable[[str, str, str], tuple[int, bytes, dict[str, Any]]] = request_simulator,
    max_polls: int = 90,
    poll_interval_seconds: float = 10,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    validate_inputs(flow_definition_id, organization_id, issuer_did, references,
                    physical_document, operator_cookie, api_key, simulator_container_id,
                    max_polls, poll_interval_seconds)

    definition_path = f"/v1/flows/definitions/{quote(flow_definition_id, safe='')}"
    status, definition = request("GET", definition_path, None, operator_cookie)
    if (status != 200 or definition.get("id") != flow_definition_id
            or definition.get("organization_id") != organization_id
            or definition.get("flow_type") != "physical_document_issuance"
            or str(definition.get("status")).upper() != "ACTIVE"
            or definition.get("resolved_steps") != list(PHYSICAL_STEPS)
            or any(definition.get(key) != references[key] for key in REFERENCES)):
        raise SelectedFlowError("Active beta passport Flow definition does not match the selected organization and templates")

    start_body = {"organization_id": organization_id, "flow_definition_id": flow_definition_id,
                  "initial_context": {"physical_document": physical_document}}
    status, current = request("POST", "/v1/flows/instances", start_body, operator_cookie)
    instance_id = current.get("id")
    if status != 200 or not isinstance(instance_id, str) or not IDENTIFIER.fullmatch(instance_id):
        raise SelectedFlowError("Selected beta passport Flow did not start")
    application_id = None
    source_job_id = None
    bureau_job_id = None
    sod_sha256 = None
    receipt = None
    callback_receipt_sha256 = None
    expected_batch_bureau_job_id = None

    def checked_job(response: dict[str, Any], expected_step: str | None,
                    expected_state: str) -> dict[str, Any]:
        nonlocal application_id, source_job_id
        context = response.get("context_data")
        job = context.get("physical_document_job") if isinstance(context, dict) else None
        if (response.get("id") != instance_id or response.get("flow_id") != flow_definition_id
                or response.get("organization_id") != organization_id
                or response.get("flow_type") != "physical_document_issuance"
                or str(response.get("status")).upper() != expected_state
                or response.get("current_step") != expected_step
                or not isinstance(job, dict)
                or job.get("organization_id") != organization_id
                or job.get("flow_execution_id") != instance_id
                or job.get("issuer_did") != issuer_did):
            raise SelectedFlowError("Selected Flow instance or managed issuer binding changed")
        if application_id is None:
            application_id = job.get("application_id")
            source_job_id = job.get("id")
            if not all(isinstance(value, str) and value for value in (application_id, source_job_id)):
                raise SelectedFlowError("Selected Flow created no passport job")
        if (job.get("application_id") != application_id or job.get("id") != source_job_id
                or context.get("application_id") != application_id
                or (bureau_job_id is not None and job.get("bureau_job_id") != bureau_job_id)
                or (sod_sha256 is not None and job.get("sod_sha256") != sod_sha256)):
            raise SelectedFlowError("Selected Flow passport job changed")
        return job

    checked_job(current, PHYSICAL_STEPS[0], "IN_PROGRESS")
    instance_path = f"/v1/flows/instances/{quote(instance_id, safe='')}"
    for index, step in enumerate(PHYSICAL_STEPS):
        read_status, current = request("GET", instance_path, None, operator_cookie)
        if read_status != 200:
            raise SelectedFlowError("Selected Flow durable instance read failed")
        checked_job(current, step, "IN_PROGRESS")
        if step == "track_production":
            try:
                canonical_bureau_id = str(UUID(bureau_job_id))
            except (TypeError, ValueError, AttributeError) as exc:
                raise SelectedFlowError("Selected Flow bureau job identity is invalid") from exc
            if canonical_bureau_id != bureau_job_id:
                raise SelectedFlowError("Selected Flow bureau job identity is not canonical")
            prior_order = -1
            for poll in range(max_polls):
                private_status, _, private_job = simulator_request(
                    simulator_container_id, "GET", f"/v1/personalization/jobs/{bureau_job_id}",
                )
                private_state = private_job.get("status")
                if (private_status != 200 or private_state not in STATUS_ORDER
                        or STATUS_ORDER[private_state] < prior_order):
                    raise SelectedFlowError("Selected Flow private simulator status regressed or poll failed")
                prior_order = STATUS_ORDER[private_state]
                if private_state == "SHIPPED":
                    callback_receipt_sha256 = private_job.get("callback_receipt_sha256")
                    if (private_job.get("tracking_number") != "BETA-SIM-" + UUID(bureau_job_id).hex
                            or not isinstance(callback_receipt_sha256, str)
                            or SHA256.fullmatch(callback_receipt_sha256) is None):
                        raise SelectedFlowError("Selected Flow signed callback receipt is missing")
                    break
                if poll + 1 < max_polls:
                    sleep(poll_interval_seconds)
            else:
                raise SelectedFlowError("Selected Flow simulator callback did not reach SHIPPED")
            status_path = f"/v1/passport/applications/{quote(application_id, safe='')}/production-status"
            for poll in range(max_polls):
                code, native = passport_request("GET", status_path, None, api_key)
                if (code != 200 or native.get("organization_id") != organization_id
                        or native.get("application_id") != application_id
                        or native.get("id") != source_job_id
                        or native.get("bureau_job_id") != bureau_job_id
                        or native.get("flow_execution_id") != instance_id
                        or native.get("issuer_did") != issuer_did):
                    raise SelectedFlowError("Selected Flow native job status changed")
                if native.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"):
                    break
                if native.get("status") in ("FAILED", "CANCELLED", "ACTIVE"):
                    raise SelectedFlowError("Selected Flow bureau reached an invalid status")
                if poll + 1 < max_polls:
                    sleep(poll_interval_seconds)
            else:
                raise SelectedFlowError("Selected Flow bureau did not reach quality check")
        body = {"step_result": "success", "data": ({"passed": True, "failure_codes": []}
                                                   if step == "quality_verify" else {})}
        status, current = request("POST", instance_path + "/advance", body, operator_cookie)
        if status != 200:
            raise SelectedFlowError("Selected Flow step did not advance")
        # The Flow projection retains the last protocol step name after the
        # kernel enters COMPLETED with no next graph edge.
        next_step = PHYSICAL_STEPS[index + 1] if index + 1 < len(PHYSICAL_STEPS) else step
        job = checked_job(current, next_step,
                          "COMPLETED" if index + 1 == len(PHYSICAL_STEPS) else "IN_PROGRESS")
        if step == "sign_sod":
            sod_sha256 = job.get("sod_sha256")
            if (not isinstance(sod_sha256, str) or not SHA256.fullmatch(sod_sha256)
                    or job.get("sod_signature_verified") is not True):
                raise SelectedFlowError("Selected Flow SOD signature is unverified")
            if on_signed_sod is not None:
                paused_status, paused = request("GET", instance_path, None, operator_cookie)
                paused_job = checked_job(paused, "submit_to_personalization", "IN_PROGRESS")
                issuer_profile_id = paused_job.get("issuer_profile_id")
                if (paused_status != 200 or paused_job.get("status") != "SOD_SIGNED"
                        or paused_job.get("sod_sha256") != sod_sha256
                        or paused_job.get("sod_signature_verified") is not True
                        or not isinstance(issuer_profile_id, str) or not issuer_profile_id):
                    raise SelectedFlowError("Selected Flow signed job is not durably paused")
                expected_batch_bureau_job_id = on_signed_sod(
                    instance_id, application_id, source_job_id, sod_sha256, issuer_profile_id)
                try:
                    canonical_bureau_id = str(UUID(expected_batch_bureau_job_id))
                except (TypeError, ValueError, AttributeError) as exc:
                    raise SelectedFlowError("Native batch did not bind the selected Flow job") from exc
                if canonical_bureau_id != expected_batch_bureau_job_id:
                    raise SelectedFlowError("Native batch selected bureau identity is not canonical")
        if step == "submit_to_personalization":
            bureau_job_id = job.get("bureau_job_id")
            if (not isinstance(bureau_job_id, str) or not bureau_job_id
                    or job.get("sod_sha256") != sod_sha256
                    or (expected_batch_bureau_job_id is not None
                        and bureau_job_id != expected_batch_bureau_job_id)):
                raise SelectedFlowError("Selected Flow submitted different SOD material")
            receipt = on_submission(organization_id, source_job_id, bureau_job_id, sod_sha256)
            evidence = receipt.get("evidence") if isinstance(receipt, dict) else None
            if (not isinstance(receipt, dict) or receipt.get("verified") is not True
                    or not isinstance(evidence, dict)
                    or evidence.get("tenant_and_job_binding") is not True
                    or evidence.get("first_accepted_sod_der_matches_native") is not True
                    or evidence.get("first_accepted_dsc_der_matches_selected_chain") is not True
                    or evidence.get("first_accepted_dsc_pem_wire_matches_selected_chain") is not True
                    or any(not isinstance(evidence.get(key), str) or not SHA256.fullmatch(evidence[key])
                           for key in ("source_job_id_commitment", "bureau_job_id_commitment"))):
                raise SelectedFlowError("Selected Flow simulator material receipt is unverified")

    read_status, current = request("GET", instance_path, None, operator_cookie)
    if read_status != 200:
        raise SelectedFlowError("Selected Flow final durable instance read failed")
    checked_job(current, PHYSICAL_STEPS[-1], "COMPLETED")
    results = current.get("step_results")
    job = current["context_data"]["physical_document_job"]
    if (str(current.get("status")).upper() != "COMPLETED"
            or not current.get("completed_at") or job.get("status") != "ACTIVE"
            or job.get("bureau_job_id") != bureau_job_id or not job.get("completed_at")
            or not isinstance(results, dict) or set(results) != set(PHYSICAL_STEPS)
            or any(str(value.get("result", value.get("status", ""))).upper() not in ("SUCCESS", "COMPLETED")
                   for value in results.values() if isinstance(value, dict))
            or any(not isinstance(value, dict) for value in results.values())):
        raise SelectedFlowError("Selected Flow did not complete all nine durable steps")
    terminal_path = f"/v1/passport/applications/{quote(application_id, safe='')}/production-status"
    terminal_status, terminal = passport_request("GET", terminal_path, None, api_key)
    if (terminal_status != 200 or terminal.get("organization_id") != organization_id
            or terminal.get("application_id") != application_id
            or terminal.get("id") != source_job_id
            or terminal.get("bureau_job_id") != bureau_job_id
            or terminal.get("flow_execution_id") != instance_id
            or terminal.get("issuer_did") != issuer_did
            or terminal.get("tracking_number") != "BETA-SIM-" + UUID(bureau_job_id).hex
            or terminal.get("status") != "ACTIVE" or not terminal.get("completed_at")):
        raise SelectedFlowError("Selected Flow terminal native job did not persist")
    return {"verified": True, "evidence": {
        "organization_id": organization_id, "flow_id": flow_definition_id,
        "flow_instance_id": instance_id, "application_id": application_id,
        "job_id": source_job_id, "bureau_job_id": bureau_job_id,
        "sod_sha256": sod_sha256, "ordered_steps": list(PHYSICAL_STEPS),
        "completed_steps": len(PHYSICAL_STEPS),
        "source_job_commitment": receipt["evidence"]["source_job_id_commitment"],
        "bureau_job_commitment": receipt["evidence"]["bureau_job_id_commitment"],
        "callback_receipt_sha256": callback_receipt_sha256,
        "signed_simulator_callback_verified": True,
        "terminal_native_status": "ACTIVE",
        "physical_claim": "not_claimed",
    }}
