#!/usr/bin/env python3
"""Rebind the completed v1.1.240 fence to a newer signed source without SQL writes."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

try:
    from .check_passport_beta_fence_authority import (
        APPROVAL, DRAIN, INSTALL, ROOT, VERIFY, check_authority,
        manifest_source, require, run,
    )
    from .probe_passport_beta_cutover_snapshot import collect
    from .probe_passport_beta_host import HostProbeError
except ImportError:
    from check_passport_beta_fence_authority import (
        APPROVAL, DRAIN, INSTALL, ROOT, VERIFY, check_authority,
        manifest_source, require, run,
    )
    from probe_passport_beta_cutover_snapshot import collect
    from probe_passport_beta_host import HostProbeError


PRIOR_SOURCE = "1b37f12bb29285fe2d1f92f279ca41aa24ee7037"
PRIOR_RELEASE = "marty-ui@1.1.240"
NEXT_RELEASE = "marty-ui@1.1.241"
SQL_FILES = (INSTALL, DRAIN, VERIFY)


def rebind_authority(
    stack_manifest: Path, baseline_manifest: Path, prior_manifest: Path,
    preinstall_target_path: Path, prior_receipt_path: Path,
) -> dict:
    target_path = preinstall_target_path.resolve(strict=True)
    receipt_path = prior_receipt_path.resolve(strict=True)
    protected_root = ROOT.resolve()
    require(target_path.is_file() and not target_path.is_relative_to(protected_root)
            and receipt_path.is_file() and not receipt_path.is_relative_to(protected_root),
            "Fence rebind inputs must be outside protected source")
    target = json.loads(target_path.read_text(encoding="utf-8-sig"))
    prior_bytes = receipt_path.read_bytes()
    prior = json.loads(prior_bytes.decode("utf-8-sig"))
    require(isinstance(target, dict) and isinstance(prior, dict)
            and prior.get("schema") == "marty.passport-beta-fence-installation/v1"
            and prior.get("source_commit") == PRIOR_SOURCE
            and "rebind" not in prior,
            "Completed v1.1.240 fence receipt is invalid")
    plan = check_authority(APPROVAL, stack_manifest, baseline_manifest,
                           observer=lambda: target)
    source = plan["source"]
    require(source["release"] == NEXT_RELEASE,
            "Fence rebind requires the next signed release")
    old = manifest_source(prior_manifest, PRIOR_SOURCE, rust_only=True)
    require(old["release"] == PRIOR_RELEASE,
            "Prior signed fence release is invalid")
    run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor",
         PRIOR_SOURCE, source["source_commit"]])
    for path in SQL_FILES:
        relative = path.relative_to(ROOT).as_posix()
        old_bytes = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{PRIOR_SOURCE}:{relative}"],
            check=True, capture_output=True, timeout=30,
        ).stdout
        require(hashlib.sha256(old_bytes).digest()
                == hashlib.sha256(path.read_bytes()).digest(),
                f"Fence SQL changed since {PRIOR_RELEASE}: {relative}")
    require(prior.get("verify_sql_sha256")
            == hashlib.sha256(VERIFY.read_bytes()).hexdigest()
            and prior.get("approved_target_observation_sha256")
                == plan["target_observation_sha256"]
            and prior.get("production_snapshot_sha256")
                == plan["production_snapshot_sha256"]
            and prior.get("production_attachments_sha256")
                == plan["production_attachments_sha256"]
            and prior.get("beta_services") == plan["beta_services"]
            and prior.get("postgres_container_id") == plan["postgres_container_id"]
            and prior.get("postgres_system_identifier")
                == plan["postgres_system_identifier"]
            and prior.get("database_oid") == plan["database_oid"],
            "Prior receipt differs from approved beta or production identity")
    # This is the same live fence, drain, production, and rollback-only write
    # probe used by the protected readiness producer. It never reinstalls SQL.
    snapshot = collect(prior)
    require(snapshot["fence_epoch"] == prior["fence"]["epoch"]
            and snapshot["production_snapshot_sha256"]
                == plan["production_snapshot_sha256"]
            and snapshot["production_attachments_sha256"]
                == plan["production_attachments_sha256"],
            "Fresh fenced beta or production evidence changed")
    receipt = deepcopy(prior)
    receipt["source_commit"] = source["source_commit"]
    receipt["direct_database_probe"] = snapshot["direct_database_probe"]
    receipt["post_install_observation_sha256"] = (
        snapshot["beta_inventory_attestation_sha256"])
    prior_hash = hashlib.sha256(prior_bytes).hexdigest()
    receipt["rebind"] = {
        "schema": "marty.passport-beta-fence-source-rebind/v1",
        "prior_source_commit": PRIOR_SOURCE,
        "prior_receipt_file_sha256": prior_hash,
        "prior_signed_manifest_sha256": old["manifest_sha256"],
        "new_signed_manifest_sha256": source["manifest_sha256"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "observed_at_utc": snapshot["observed_at_utc"],
        "fence_sql_unchanged": True,
    }
    return {
        "schema": "marty.passport-beta-fence-rebind-plan/v1",
        "verified": True,
        "source_commit": source["source_commit"],
        "prior_source_commit": PRIOR_SOURCE,
        "prior_receipt_file_sha256": prior_hash,
        "receipt": receipt,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--beta-baseline-manifest", type=Path, required=True)
    parser.add_argument("--prior-stack-manifest", type=Path, required=True)
    parser.add_argument("--preinstall-target", type=Path, required=True)
    parser.add_argument("--prior-receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(rebind_authority(
            args.stack_manifest, args.beta_baseline_manifest,
            args.prior_stack_manifest, args.preinstall_target,
            args.prior_receipt,
        ), sort_keys=True, separators=(",", ":")))
    except (HostProbeError, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as exc:
        raise SystemExit(f"Beta fence source rebind is not authorized: {exc}") from exc
