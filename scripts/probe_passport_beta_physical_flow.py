#!/usr/bin/env python3
"""Bind one beta physical-document Flow to its native simulator receipt."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

if __package__:
    from .probe_passport_beta_flow import PHYSICAL_STEPS
    from .probe_passport_beta_gateway import request_beta as request_passport
    from .probe_passport_beta_batch import (
        CONTAINER_ID, SHA256, STATUS_ORDER, _request as request_simulator,
    )
else:
    from probe_passport_beta_flow import PHYSICAL_STEPS
    from probe_passport_beta_gateway import request_beta as request_passport
    from probe_passport_beta_batch import (
        CONTAINER_ID, SHA256, STATUS_ORDER, _request as request_simulator,
    )

ORIGIN = "https://beta.elevenidllc.com"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,255}\Z")


class PhysicalFlowProbeError(ValueError):
    pass


def validate_operator_session(session: str | None) -> None:
    if not isinstance(session, str) or not session or any(char in session for char in "\r\n"):
        raise PhysicalFlowProbeError("Flow operator session is invalid")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def require_source_checkout(source_commit: str) -> None:
    """Run only checked-in probe/contract code from the signed UI source."""
    checkout = Path(__file__).resolve().parents[1]
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all", "--", "scripts", "contracts"],
            cwd=checkout, check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise PhysicalFlowProbeError("Physical Flow source checkout could not be verified") from exc
    if head != source_commit or status:
        raise PhysicalFlowProbeError("Physical Flow probe source checkout drifted")


def request_beta(method: str, path: str, body: dict[str, Any] | None, session: str) -> tuple[int, dict[str, Any]]:
    if method not in ("POST", "GET") or not re.fullmatch(
        r"/v1/flows/instances(?:/[A-Za-z0-9_-]{1,255}(?:/advance)?)?", path,
    ):
        raise PhysicalFlowProbeError("Unexpected Flow route")
    validate_operator_session(session)
    url = ORIGIN + path
    encoded = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    headers = {"Accept": "application/json", "Cache-Control": "no-cache",
               "User-Agent": "passport-beta-acceptance/1", "Cookie": session}
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    try:
        with build_opener(ProxyHandler({}), NoRedirect).open(
            Request(url, data=encoded, headers=headers, method=method), timeout=120,
        ) as response:
            if response.geturl() != url:
                raise PhysicalFlowProbeError("Flow route redirected")
            raw = response.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise PhysicalFlowProbeError("Flow response is oversized")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise PhysicalFlowProbeError("Flow response is invalid")
            return response.status, payload
    except HTTPError as exc:
        return exc.code, {}
    except (OSError, URLError, ValueError) as exc:
        raise PhysicalFlowProbeError("Flow request failed") from exc


def validate_plan(plan: dict[str, Any], release: dict[str, Any], deployment: dict[str, Any]) -> None:
    if (not isinstance(plan, dict) or set(plan) != {"source_commit", "stack_manifest_sha256",
            "organization_id", "flow_definition_id", "issuer_did", "physical_document"}):
        raise PhysicalFlowProbeError("Physical Flow plan is incomplete")
    if (release.get("signed_manifest_verified") is not True
            or deployment.get("provider_mode") != "simulator"
            or not isinstance(plan["source_commit"], str)
            or SHA.fullmatch(plan["source_commit"]) is None
            or plan["source_commit"] != release.get("source_commit")
            or not isinstance(plan["stack_manifest_sha256"], str)
            or DIGEST.fullmatch(plan["stack_manifest_sha256"]) is None
            or plan["stack_manifest_sha256"] != release.get("stack_manifest_sha256")):
        raise PhysicalFlowProbeError("Physical Flow plan does not match signed simulator release")
    for key in ("organization_id", "flow_definition_id"):
        if not isinstance(plan[key], str) or IDENTIFIER.fullmatch(plan[key]) is None:
            raise PhysicalFlowProbeError("Physical Flow identity is invalid")
    if not isinstance(plan["issuer_did"], str) or not plan["issuer_did"].startswith("did:"):
        raise PhysicalFlowProbeError("Physical Flow managed issuer DID is invalid")
    physical = plan["physical_document"]
    if (not isinstance(physical, dict)
            or set(physical) not in (
                {"country_code", "applicant", "mrz", "data_groups"},
                {"country_code", "applicant", "mrz", "data_groups", "document_type"},
            )
            or not isinstance(physical.get("country_code"), str)
            or re.fullmatch(r"[A-Z]{3}", physical["country_code"]) is None
            or not isinstance(physical.get("applicant"), dict)
            or not physical["applicant"]
            or not isinstance(physical.get("mrz"), dict)
            or not physical["mrz"]
            or any(not isinstance(value, str) for value in physical["mrz"].values())
            or ("document_type" in physical and physical["document_type"] not in ("TD1", "TD2", "TD3"))):
        raise PhysicalFlowProbeError("Physical document inputs are incomplete")
    groups = physical.get("data_groups")
    if (not isinstance(groups, dict) or not {"DG1", "DG2"} <= set(groups)
            or any(not isinstance(name, str) or re.fullmatch(r"DG[0-9]+", name) is None
                   or not isinstance(content, str) for name, content in groups.items())):
        raise PhysicalFlowProbeError("Physical document data groups are invalid")
    try:
        for content in groups.values():
            decoded = base64.b64decode(content, validate=True)
            if not decoded or base64.b64encode(decoded).decode("ascii") != content:
                raise ValueError("noncanonical data group")
    except (ValueError, base64.binascii.Error) as exc:
        raise PhysicalFlowProbeError("Physical document data groups are invalid") from exc


def exercise(
    plan: dict[str, Any], release: dict[str, Any], deployment: dict[str, Any],
    simulator_container_id: str, session: str, api_key: str,
    *, request: Callable[[str, str, dict[str, Any] | None, str], tuple[int, dict[str, Any]]] = request_beta,
    status_request: Callable[[str, str, dict[str, Any] | None, str], tuple[int, dict[str, Any]]] = request_passport,
    simulator_request: Callable[..., tuple[int, bytes, dict[str, Any]]] = request_simulator,
    nonce: Callable[[], str] = lambda: secrets.token_hex(16),
    source_checker: Callable[[str], None] = require_source_checkout,
    max_polls: int = 90,
    poll_interval_seconds: float = 10,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    validate_plan(plan, release, deployment)
    if CONTAINER_ID.fullmatch(simulator_container_id) is None:
        raise PhysicalFlowProbeError("Inspected beta simulator identity is invalid")
    source_checker(plan["source_commit"])
    validate_operator_session(session)
    if not isinstance(api_key, str) or len(api_key) < 32:
        raise PhysicalFlowProbeError("Flow operator session or passport API key is unavailable")
    if not 1 <= max_polls <= 180 or poll_interval_seconds < 0:
        raise PhysicalFlowProbeError("Invalid bounded simulator polling policy")
    run_id = nonce()
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise PhysicalFlowProbeError("Physical Flow run identity is invalid")
    organization_id = plan["organization_id"]
    definition_id = plan["flow_definition_id"]
    body = {"organization_id": organization_id, "flow_definition_id": definition_id,
            "external_reference": "passport-beta-" + run_id,
            "initial_context": {"physical_document": plan["physical_document"]}}
    status, started = request("POST", "/v1/flows/instances", body, session)
    instance_id = started.get("id")
    if status != 200 or not isinstance(instance_id, str) or IDENTIFIER.fullmatch(instance_id) is None:
        raise PhysicalFlowProbeError("Physical Flow did not start")
    path = "/v1/flows/instances/" + quote(instance_id, safe="")

    bound_job: tuple[str, str] | None = None
    bound_bureau_job_id: str | None = None
    sod_sha256: str | None = None
    callback_receipt_sha256: str | None = None

    def check(payload: dict[str, Any], step: str | None, expected_status: str) -> None:
        nonlocal bound_job, bound_bureau_job_id
        if (payload.get("id") != instance_id or payload.get("organization_id") != organization_id
                or payload.get("flow_id") != definition_id
                or payload.get("flow_type") != "physical_document_issuance"
                or payload.get("current_step") != step or payload.get("status") != expected_status
                or not isinstance(payload.get("metadata"), dict)
                or payload["metadata"].get("external_reference") != "passport-beta-" + run_id):
            raise PhysicalFlowProbeError("Physical Flow identity, step, or state drifted")
        context = payload.get("context_data")
        job = context.get("physical_document_job") if isinstance(context, dict) else None
        application_id = job.get("application_id") if isinstance(job, dict) else None
        job_id = job.get("id") if isinstance(job, dict) else None
        bureau_job_id = job.get("bureau_job_id") if isinstance(job, dict) else None
        if (not isinstance(application_id, str) or IDENTIFIER.fullmatch(application_id) is None
                or not isinstance(job_id, str) or not job_id
                or job.get("issuer_did") != plan["issuer_did"]
                or job.get("flow_execution_id") != instance_id
                or job.get("organization_id") != organization_id):
            raise PhysicalFlowProbeError("Physical Flow has no durable job binding")
        current_job = (application_id, job_id)
        if bound_job is None:
            bound_job = current_job
        elif current_job != bound_job:
            raise PhysicalFlowProbeError("Physical Flow durable job identity drifted")
        if bureau_job_id is not None:
            if not isinstance(bureau_job_id, str) or not bureau_job_id:
                raise PhysicalFlowProbeError("Physical Flow bureau job identity is invalid")
            if bound_bureau_job_id is None:
                bound_bureau_job_id = bureau_job_id
            elif bureau_job_id != bound_bureau_job_id:
                raise PhysicalFlowProbeError("Physical Flow durable job identity drifted")
        elif bound_bureau_job_id is not None:
            raise PhysicalFlowProbeError("Physical Flow durable job identity drifted")

    check(started, PHYSICAL_STEPS[0], "IN_PROGRESS")
    observed = []
    for index, step in enumerate(PHYSICAL_STEPS):
        status, current = request("GET", path, None, session)
        if status != 200:
            raise PhysicalFlowProbeError("Physical Flow read failed")
        check(current, step, "IN_PROGRESS")
        if step == "track_production":
            if bound_job is None or bound_bureau_job_id is None:
                raise PhysicalFlowProbeError("Physical Flow has no durable bureau job binding")
            application_id, job_id = bound_job
            bureau_job_id = bound_bureau_job_id
            try:
                canonical_bureau_id = str(UUID(bureau_job_id))
            except ValueError as exc:
                raise PhysicalFlowProbeError("Physical Flow bureau job ID is not canonical") from exc
            if canonical_bureau_id != bureau_job_id:
                raise PhysicalFlowProbeError("Physical Flow bureau job ID is not canonical")
            prior_order = -1
            for poll in range(max_polls):
                private_status, _, private_job = simulator_request(
                    simulator_container_id, "GET",
                    "/v1/personalization/jobs/" + bureau_job_id,
                )
                state = private_job.get("status")
                if (private_status != 200 or state not in STATUS_ORDER
                        or STATUS_ORDER[state] < prior_order):
                    raise PhysicalFlowProbeError("Private simulator job poll failed")
                prior_order = STATUS_ORDER[state]
                if state == "SHIPPED":
                    receipt = private_job.get("callback_receipt_sha256")
                    if (private_job.get("tracking_number")
                            != "BETA-SIM-" + UUID(bureau_job_id).hex
                            or not isinstance(receipt, str)
                            or SHA256.fullmatch(receipt) is None):
                        raise PhysicalFlowProbeError("Flow simulator signed receipt is missing")
                    callback_receipt_sha256 = receipt
                    break
                if poll + 1 < max_polls:
                    sleep(poll_interval_seconds)
            else:
                raise PhysicalFlowProbeError("Flow simulator callback did not reach SHIPPED")
            status_path = "/v1/passport/applications/" + quote(application_id, safe="") + "/production-status"
            for poll in range(max_polls):
                http_status, production = status_request("GET", status_path, None, api_key)
                if (http_status != 200 or production.get("organization_id") != organization_id
                        or production.get("application_id") != application_id
                        or production.get("flow_execution_id") != instance_id
                        or production.get("id") != job_id
                        or production.get("bureau_job_id") != bureau_job_id
                        or production.get("issuer_did") != plan["issuer_did"]):
                    raise PhysicalFlowProbeError("Physical simulator job identity drifted")
                if production.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"):
                    break
                if production.get("status") in ("FAILED", "CANCELLED", "ACTIVE"):
                    raise PhysicalFlowProbeError("Physical simulator job reached invalid state")
                if poll + 1 < max_polls:
                    sleep(poll_interval_seconds)
            else:
                raise PhysicalFlowProbeError("Physical simulator callback did not reach quality check")
        data = {"passed": True, "failure_codes": []} if step == "quality_verify" else {}
        status, advanced = request("POST", path + "/advance", {"step_result": "success", "data": data}, session)
        if status != 200:
            raise PhysicalFlowProbeError("Physical Flow advance failed")
        next_step = PHYSICAL_STEPS[index + 1] if index + 1 < len(PHYSICAL_STEPS) else step
        check(advanced, next_step, "COMPLETED" if index + 1 == len(PHYSICAL_STEPS) else "IN_PROGRESS")
        if step == "sign_sod":
            job = advanced.get("context_data", {}).get("physical_document_job")
            digest = job.get("sod_sha256") if isinstance(job, dict) else None
            if (not isinstance(digest, str) or SHA256.fullmatch(digest) is None
                    or job.get("sod_signature_verified") is not True):
                raise PhysicalFlowProbeError("Flow managed SOD signature was not verified")
            sod_sha256 = digest
        if step == "track_production":
            context = advanced.get("context_data")
            job = context.get("physical_document_job") if isinstance(context, dict) else None
            if not isinstance(job, dict) or job.get("status") not in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"):
                raise PhysicalFlowProbeError("Simulator callback has not reached quality check")
        observed.append(step)
    status, final = request("GET", path, None, session)
    if status != 200:
        raise PhysicalFlowProbeError("Physical Flow final read failed")
    check(final, PHYSICAL_STEPS[-1], "COMPLETED")
    if (bound_job is None or bound_bureau_job_id is None or sod_sha256 is None
            or callback_receipt_sha256 is None):
        raise PhysicalFlowProbeError("Physical Flow has no durable bureau job binding")
    terminal_path = "/v1/passport/applications/" + quote(bound_job[0], safe="") + "/production-status"
    terminal_status, terminal = status_request("GET", terminal_path, None, api_key)
    if (terminal_status != 200 or terminal.get("organization_id") != organization_id
            or terminal.get("flow_execution_id") != instance_id
            or terminal.get("application_id") != bound_job[0]
            or terminal.get("id") != bound_job[1]
            or terminal.get("issuer_did") != plan["issuer_did"]
            or terminal.get("bureau_job_id") != bound_bureau_job_id
            or terminal.get("tracking_number") != "BETA-SIM-" + UUID(bound_bureau_job_id).hex
            or terminal.get("status") != "ACTIVE" or not terminal.get("completed_at")):
        raise PhysicalFlowProbeError("Flow terminal native passport job did not persist")
    return {"verified": True, "evidence": {
        "source_commit": plan["source_commit"],
        "stack_manifest_sha256": plan["stack_manifest_sha256"],
        "instance_id_sha256": hashlib.sha256(instance_id.encode()).hexdigest(),
        "application_id_sha256": hashlib.sha256(bound_job[0].encode()).hexdigest(),
        "job_id_sha256": hashlib.sha256(bound_job[1].encode()).hexdigest(),
        "bureau_job_id_sha256": hashlib.sha256(bound_bureau_job_id.encode()).hexdigest(),
        "sod_sha256": sod_sha256,
        "sod_signature_verified": True,
        "callback_receipt_sha256": callback_receipt_sha256,
        "provider_kind": "simulator",
        "physical_claim": "not_claimed",
        "run_id_sha256": hashlib.sha256(run_id.encode()).hexdigest(),
        "steps": observed,
        "execution_relationship": "not_compared_to_gateway_lifecycle",
        "signed_simulator_callback_verified": True,
        "terminal_native_status": "ACTIVE",
    }}
