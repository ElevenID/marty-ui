#!/usr/bin/env python3
"""Verify a protected plan and blocked Rust producer receipt before attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Callable

if __package__:
    from .check_passport_supported_rust_model import PROJECT
    from .passport_supported_certificate_rehearsal import validate_certificate_setup
    from .passport_supported_protected_producer import _application
    from .passport_supported_provisioning_producer import ProducerError
    from .probe_passport_supported_routes import _frozen_routes
    from .passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, _attest,
    )
else:
    from check_passport_supported_rust_model import PROJECT
    from passport_supported_certificate_rehearsal import validate_certificate_setup
    from passport_supported_protected_producer import _application
    from passport_supported_provisioning_producer import ProducerError
    from probe_passport_supported_routes import _frozen_routes
    from passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, _attest,
    )


class HandoffError(ValueError):
    pass


HASH = re.compile(r"[0-9a-f]{64}\Z")
BLOCKER = "Flow execution and Rust restart/resume remain unproven"
RECEIPT_FIELDS = frozenset({
    "schema", "status", "project", "surface", "source_commit", "gateway_port",
    "physical_claim", "plan_run_id", "producer_run_id",
    "certificate_setup_passed", "live_ownership_verified", "rust_routes_verified",
    "signed_gateway_callback_verified", "flow_execution_verified",
    "rust_restart_resume_verified", "certificate", "route", "blocker",
})
ROUTE_EVIDENCE_FIELDS = frozenset({
    "application_input_sha256", "job_id_sha256", "application_id_sha256",
    "bureau_job_id_sha256", "sod_sha256", "sod_signature_verified", "routes",
    "callback_receipt_sha256", "callback_bureau_job_id_sha256",
    "callback_private_status", "unsigned_webhook_http_status",
    "signed_callback_path", "signed_gateway_callback_verified", "physical_claim",
})


def _route_evidence(route: object, gateway_port: int) -> None:
    evidence = route.get("evidence") if isinstance(route, dict) else None
    if (not isinstance(route, dict) or set(route) != {
            "verified", "evidence", "flow_execution_verified"}
        or route.get("verified") is not True
        or route.get("flow_execution_verified") is not False
        or not isinstance(evidence, dict)
        or set(evidence) != ROUTE_EVIDENCE_FIELDS
        or evidence.get("sod_signature_verified") is not True
        or evidence.get("signed_gateway_callback_verified") is not True
        or evidence.get("signed_callback_path") != "simulator-to-gateway-to-native"
        or evidence.get("physical_claim") != "not_claimed"
        or evidence.get("unsigned_webhook_http_status") != 422
        or evidence.get("callback_private_status") not in {"QUALITY_CHECK", "SHIPPED"}
        or not isinstance(evidence.get("routes"), list)
        or len(evidence["routes"]) < 9):
        raise HandoffError("Protected Rust route proof is invalid")
    hashes = (
        "application_input_sha256", "job_id_sha256", "application_id_sha256",
        "bureau_job_id_sha256", "sod_sha256", "callback_receipt_sha256",
        "callback_bureau_job_id_sha256",
    )
    expected_application = hashlib.sha256(json.dumps(
        _application(gateway_port), sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    if (any(type(evidence.get(name)) is not str
            or HASH.fullmatch(evidence[name]) is None for name in hashes)
        or evidence["application_input_sha256"] != expected_application
        or evidence["callback_bureau_job_id_sha256"] != evidence["bureau_job_id_sha256"]):
        raise HandoffError("Protected Rust job or callback hash is invalid")
    routes = evidence["routes"]
    if (not all(isinstance(item, dict)
                and isinstance(item.get("method"), str)
                and isinstance(item.get("route"), str)
                and type(item.get("http_status")) is int
                and (item["http_status"] == 422
                     if item.get("route") == "/v1/passport/webhooks/personalization"
                     else item["http_status"] == 201
                     if item.get("route") == "/v1/passport/applications"
                     else item["http_status"] == 200)
                for item in routes)
        or {(item["method"], item["route"]) for item in routes} != _frozen_routes()):
        raise HandoffError("Protected Rust route status proof is invalid")
    capability_path = "/v1/passport/capabilities"
    webhook_path = "/v1/passport/webhooks/personalization"
    production_path = "/v1/passport/applications/{application_id}/production-status"
    for path in {item["route"] for item in routes}:
        found = [item for item in routes if item["route"] == path]
        if len(found) != 1 and path != production_path:
            raise HandoffError("Protected Rust route count is invalid")
        expected_fields = {"method", "route", "http_status"}
        if path == webhook_path:
            expected_fields |= {"positive_gateway_path_verified",
                                "signed_callback_observed_by"}
        elif path != capability_path:
            expected_fields.add("job_status")
        if any(set(item) != expected_fields
               or ("job_status" in expected_fields
                   and (not isinstance(item["job_status"], str)
                        or not 1 <= len(item["job_status"]) <= 64))
               for item in found):
            raise HandoffError("Protected Rust route entry is invalid")
    statuses = {
        "/v1/passport/applications": "DRAFT",
        "/v1/passport/applications/{application_id}/generate-data-groups": "DATA_GENERATED",
        "/v1/passport/applications/{application_id}/generate-sod": "SOD_SIGNED",
        "/v1/passport/applications/{application_id}/quality-verify": "READY_FOR_ACTIVATION",
        "/v1/passport/applications/{application_id}/activate": "ACTIVE",
    }
    if (any(not any(item.get("route") == path
                    and item.get("job_status") == status for item in routes)
            for path, status in statuses.items())
        or not any(item.get("route") ==
                   "/v1/passport/applications/{application_id}/production-status"
                   and item.get("job_status") in {"QUALITY_CHECK", "READY_FOR_ACTIVATION"}
                   for item in routes)
        or not any(item.get("route") == webhook_path
                   and item.get("positive_gateway_path_verified") is True
                   and item.get("signed_callback_observed_by") ==
                   "authenticated-private-bureau-receipt" for item in routes)):
        raise HandoffError("Protected Rust lifecycle or callback boundary is invalid")


def verify_handoff(
    plan_path: Path, receipt_path: Path, source_commit: str,
    producer_run_id: str, *,
    attest: Callable[[str, str, str, str, str], bool] = _attest,
) -> dict:
    if (COMMIT.fullmatch(source_commit) is None
        or RUN_ID.fullmatch(producer_run_id) is None):
        raise HandoffError("Protected handoff source/run is invalid")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise HandoffError("Protected handoff artifact is invalid") from error
    if (not isinstance(plan, dict) or not isinstance(receipt, dict)
        or plan.get("schema") != "marty.passport-supported-provisioning-plan/v1"
        or plan.get("status") != "blocked"
        or plan.get("source_commit") != source_commit
        or not isinstance(plan.get("run_id"), str)
        or RUN_ID.fullmatch(plan["run_id"]) is None
        or not isinstance(plan.get("project"), str)
        or (match := PROJECT.fullmatch(plan["project"])) is None
        or match.group(1) != plan.get("surface")
        or receipt.get("schema") != "marty.passport-supported-rust-producer/v1"
        or set(receipt) != RECEIPT_FIELDS
        or receipt.get("status") != "blocked"
        or receipt.get("source_commit") != source_commit
        or receipt.get("producer_run_id") != producer_run_id
        or receipt.get("plan_run_id") != plan.get("run_id")
        or receipt.get("project") != plan.get("project")
        or receipt.get("surface") != plan.get("surface")
        or type(receipt.get("gateway_port")) is not int
        or not 1024 <= receipt["gateway_port"] <= 65535
        or receipt.get("physical_claim") != "not_claimed"
        or receipt.get("blocker") != BLOCKER
        or receipt.get("certificate_setup_passed") is not True
        or receipt.get("live_ownership_verified") is not True
        or receipt.get("rust_routes_verified") is not True
        or receipt.get("signed_gateway_callback_verified") is not True
        or receipt.get("flow_execution_verified") is not False
        or receipt.get("rust_restart_resume_verified") is not False):
        raise HandoffError("Protected Rust producer receipt differs from plan")
    certificate = receipt["certificate"]
    if (not isinstance(certificate, dict)
        or set(certificate) != {"schema", "status", "gateway_operator_authorization_verified",
                                "project", "source_commit", "evidence"}
        or not isinstance(certificate.get("evidence"), dict)
        or set(certificate["evidence"]) != {
            "csca_certificate_id", "csca_certificate_sha256", "dsc_certificate_sha256",
            "csca_issuer_did_sha256", "dsc_issuer_did_sha256",
            "csca_http_status", "dsc_http_status", "chain_verified_by"}):
        raise HandoffError("Protected managed certificate evidence is invalid")
    try:
        validate_certificate_setup(certificate, plan, receipt["gateway_port"])
    except (ProducerError, KeyError, TypeError, ValueError) as error:
        raise HandoffError("Protected managed certificate evidence is invalid") from error
    _route_evidence(receipt["route"], receipt["gateway_port"])
    try:
        verified = attest(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                          source_commit, "refs/heads/main")
    except (OSError, ValueError) as error:
        raise HandoffError("Protected plan attestation failed") from error
    if verified is not True:
        raise HandoffError("Protected plan attestation failed")
    return {"schema": "marty.passport-supported-rust-producer-handoff/v1",
            "status": "blocked", "producer_run_id": producer_run_id,
            "project": plan["project"], "source_commit": source_commit}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--producer-run-id", required=True)
    args = parser.parse_args()
    try:
        result = verify_handoff(args.plan, args.receipt, args.source_commit,
                                args.producer_run_id)
    except HandoffError as error:
        parser.exit(1, f"Protected producer handoff blocked: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
