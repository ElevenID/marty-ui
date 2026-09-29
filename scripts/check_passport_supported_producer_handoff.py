#!/usr/bin/env python3
"""Verify a protected plan and blocked Rust producer receipt before attestation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

if __package__:
    from .probe_passport_supported_routes import _frozen_routes
    from .passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, _attest,
    )
else:
    from probe_passport_supported_routes import _frozen_routes
    from passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, _attest,
    )


class HandoffError(ValueError):
    pass


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
        or receipt.get("schema") != "marty.passport-supported-rust-producer/v1"
        or receipt.get("status") != "blocked"
        or receipt.get("source_commit") != source_commit
        or receipt.get("producer_run_id") != producer_run_id
        or receipt.get("plan_run_id") != plan.get("run_id")
        or receipt.get("project") != plan.get("project")
        or receipt.get("surface") != plan.get("surface")
        or receipt.get("certificate_setup_passed") is not True
        or receipt.get("live_ownership_verified") is not True
        or receipt.get("rust_routes_verified") is not True
        or receipt.get("signed_gateway_callback_verified") is not False
        or receipt.get("flow_execution_verified") is not False
        or receipt.get("rust_restart_resume_verified") is not False):
        raise HandoffError("Protected Rust producer receipt differs from plan")
    route = receipt.get("route")
    evidence = route.get("evidence") if isinstance(route, dict) else None
    if (not isinstance(route, dict) or route.get("verified") is not True
        or route.get("flow_execution_verified") is not False
        or not isinstance(evidence, dict)
        or evidence.get("signed_gateway_callback_verified") is not False
        or not isinstance(evidence.get("routes"), list)
        or len(evidence["routes"]) < 9):
        raise HandoffError("Protected Rust route proof is invalid")
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
        or {(item.get("method"), item.get("route")) for item in routes}
        != _frozen_routes()):
        raise HandoffError("Protected Rust route status proof is invalid")
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
