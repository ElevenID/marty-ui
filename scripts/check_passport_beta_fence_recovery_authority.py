#!/usr/bin/env python3
"""Authorize completion of a fence compatible with signed v1.1.237 SQL."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

try:
    from .check_passport_beta_fence_authority import (
        APPROVAL, DRAIN, INSTALL, ROOT, VERIFY, check_authority,
        manifest_source, require, run,
    )
    from .probe_passport_beta_host import HostProbeError
except ImportError:
    from check_passport_beta_fence_authority import (
        APPROVAL, DRAIN, INSTALL, ROOT, VERIFY, check_authority,
        manifest_source, require, run,
    )
    from probe_passport_beta_host import HostProbeError


COMPATIBLE_PRIOR_SOURCE_COMMIT = "56987c4605680bf8b6e7f0091a9aa483a72ebaad"
SQL_FILES = (INSTALL, DRAIN, VERIFY)


def recovery_authority(
    stack_manifest: Path, baseline_manifest: Path,
    compatible_prior_manifest: Path, preinstall_target_path: Path,
) -> dict:
    target_path = preinstall_target_path.resolve(strict=True)
    require(target_path.is_file() and not target_path.is_relative_to(ROOT.resolve()),
            "Preinstallation observation must be outside protected source")
    target_bytes = target_path.read_bytes()
    target = json.loads(target_bytes.decode("utf-8-sig"))
    require(isinstance(target, dict), "Preinstallation observation is invalid")
    plan = check_authority(
        APPROVAL, stack_manifest, baseline_manifest,
        observer=lambda: target,
    )
    old = manifest_source(compatible_prior_manifest, COMPATIBLE_PRIOR_SOURCE_COMMIT,
                          rust_only=True)
    require(old["release"] == "marty-ui@1.1.237",
            "Compatible prior release is invalid")
    require(run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor",
                 COMPATIBLE_PRIOR_SOURCE_COMMIT, plan["source"]["source_commit"]]) == "",
            "Compatible prior source is not an ancestor of the recovery release")
    for path in SQL_FILES:
        relative = path.relative_to(ROOT).as_posix()
        installed = subprocess.run(
            ["git", "-C", str(ROOT), "show",
             f"{COMPATIBLE_PRIOR_SOURCE_COMMIT}:{relative}"],
            check=True, capture_output=True, timeout=30,
        ).stdout
        require(hashlib.sha256(installed).hexdigest()
                == hashlib.sha256(path.read_bytes()).hexdigest(),
                f"Fence SQL changed since the compatible prior release: {relative}")
    plan["preinstall_target"] = target
    plan["recovery"] = {
        "compatible_prior_source_commit": COMPATIBLE_PRIOR_SOURCE_COMMIT,
        "compatible_prior_stack_manifest_sha256": old["manifest_sha256"],
        "preinstall_target_file_sha256": hashlib.sha256(target_bytes).hexdigest(),
    }
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--beta-baseline-manifest", type=Path, required=True)
    parser.add_argument("--compatible-prior-stack-manifest", type=Path, required=True)
    parser.add_argument("--preinstall-target", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(recovery_authority(
            args.stack_manifest, args.beta_baseline_manifest,
            args.compatible_prior_stack_manifest, args.preinstall_target,
        ), sort_keys=True, separators=(",", ":")))
    except (HostProbeError, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as exc:
        raise SystemExit(f"Beta fence recovery authority is not established: {exc}") from exc
