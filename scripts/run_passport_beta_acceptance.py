#!/usr/bin/env python3
"""Execute source-bound beta probes and preserve unproven acceptance gates."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable

if __package__:
    from .collect_passport_beta_acceptance import (
        EvidenceError, collect, read_json, require, verify_attestations,
    )
    from .probe_passport_beta_gateway import ProbeError, exercise
    from .probe_passport_beta_chain import (
        ChainProbeError, exercise as exercise_chain, validate_plan, validate_sessions,
    )
    from .probe_passport_beta_host import (
        HostProbeError, assert_production_unchanged, beta_legacy_drain,
        production_snapshot,
    )
else:
    from collect_passport_beta_acceptance import (
        EvidenceError, collect, read_json, require, verify_attestations,
    )
    from probe_passport_beta_gateway import ProbeError, exercise
    from probe_passport_beta_chain import (
        ChainProbeError, exercise as exercise_chain, validate_plan, validate_sessions,
    )
    from probe_passport_beta_host import (
        HostProbeError, assert_production_unchanged, beta_legacy_drain,
        production_snapshot,
    )


def run(
    artifact_dir: Path,
    application: dict[str, Any],
    api_key: str,
    *,
    collector: Callable[..., dict[str, Any]] = collect,
    attestor: Callable[..., bool] = verify_attestations,
    snapshot: Callable[[], dict[str, Any]] = production_snapshot,
    drain: Callable[[], dict[str, Any]] = beta_legacy_drain,
    lifecycle: Callable[..., dict[str, Any]] = exercise,
    certificate_plan: dict[str, Any] | None = None,
    csca_session: str | None = None,
    dsc_session: str | None = None,
    chain: Callable[..., dict[str, Any]] = exercise_chain,
) -> dict[str, Any]:
    report = collector(artifact_dir, api_key=api_key, attest=attestor)
    require(report.get("status") == "blocked" and report.get("release", {}).get("signed_manifest_verified") is True, "Official beta release is not authenticated")
    require(report.get("probes", {}).get("capabilities_http", {}).get("verified") is True, "Managed issuer capability is not ready")
    chain_requested = any(value is not None for value in (certificate_plan, csca_session, dsc_session))
    if chain_requested:
        require(isinstance(certificate_plan, dict) and bool(csca_session) and bool(dsc_session),
                "Governed CSCA and DSC ceremony inputs are incomplete")
        validate_sessions(csca_session, dsc_session)
        validate_plan(certificate_plan)
        require(certificate_plan["organization_id"] == application.get("organization_id")
                and certificate_plan["dsc"]["dsc_issuer_did"] == application.get("issuer_did"),
                "Certificate plan does not match the passport application")
    before_production = snapshot()
    before_drain = drain()
    try:
        lifecycle_result = lifecycle(application, api_key)
        chain_result = None
        if chain_requested:
            chain_result = chain(certificate_plan, csca_session, dsc_session)
            require(chain_result.get("verified") is True and chain_result.get("evidence") is not None,
                    "Managed CSCA and DSC chain did not verify")
    finally:
        after_production = snapshot()
        production_window = assert_production_unchanged(before_production, after_production)
    after_drain = drain()
    after = collector(artifact_dir, api_key=api_key, attest=attestor)
    require(all(report[key] == after[key] for key in ("release", "deployment", "runtime_images")), "Beta release or runtime drifted during passport acceptance")
    report["probes"]["gateway_application_lifecycle"] = lifecycle_result
    if chain_result is not None:
        report["probes"]["managed_csca_dsc_chain"] = chain_result
    report["probes"]["legacy_drain"] = {
        "verified": before_drain.get("verified") is True and after_drain.get("verified") is True,
        "evidence": {"before": before_drain.get("evidence"), "after": after_drain.get("evidence")},
    }
    report["probes"]["production_continuity_during_probe"] = production_window
    # The required production-isolation gate spans deployment and rollback,
    # which this workflow does not control. Preserve it as unverified.
    report["status"] = "blocked"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--application-file", type=Path, required=True)
    parser.add_argument("--certificate-plan-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY")
        require(isinstance(api_key, str) and len(api_key) >= 32, "Passport beta API key is unavailable")
        application = read_json(args.application_file)
        certificate_plan = read_json(args.certificate_plan_file) if args.certificate_plan_file else None
        report = run(
            args.artifact_dir, application, api_key, certificate_plan=certificate_plan,
            csca_session=os.environ.get("PASSPORT_ACCEPTANCE_CSCA_OPERATOR_COOKIE"),
            dsc_session=os.environ.get("PASSPORT_ACCEPTANCE_DSC_OPERATOR_COOKIE"),
        )
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (EvidenceError, ProbeError, ChainProbeError, HostProbeError, OSError) as exc:
        args.output.write_text(json.dumps({"schema": "marty.passport-beta-acceptance/v1", "status": "blocked", "blocker": str(exc)}, indent=2) + "\n", encoding="utf-8")
        parser.exit(1, f"Passport beta acceptance blocked: {exc}\n")
    print(f"Wrote blocked passport beta acceptance evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
