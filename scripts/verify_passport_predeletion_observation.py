#!/usr/bin/env python3
"""Verify a protected beta drain observation before predeletion qualification.

The result is an attested observation, not a Rust acceptance receipt. The
predeletion producer must still prove the independent disposable Rust runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable

try:
    from .collect_passport_predeletion_drain import collect, read
    from .probe_passport_beta_host import HostProbeError
    from .verify_passport_beta_protected_cutover import utc
except ImportError:
    from collect_passport_predeletion_drain import collect, read
    from probe_passport_beta_host import HostProbeError
    from verify_passport_beta_protected_cutover import utc


REPOSITORY = "ElevenID/marty-ui"
WORKFLOW = ".github/workflows/passport-beta-predeletion-drain-observation.yml"
SIGNER = f"{REPOSITORY}/{WORKFLOW}"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
Run = Callable[[list[str]], str]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def command(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False,
                            timeout=120)
    require(result.returncode == 0, "Protected drain provenance command failed")
    return result.stdout


def parsed(value: str, message: str) -> Any:
    try:
        return json.loads(value)
    except ValueError as exc:
        raise HostProbeError(message) from exc


def verify_run(run_id: int, source_commit: str, runner: Run = command) -> dict[str, Any]:
    require(type(run_id) is int and RUN_ID.fullmatch(str(run_id)) is not None
            and isinstance(source_commit, str)
            and SHA.fullmatch(source_commit) is not None,
            "Protected drain run or source commit is invalid")
    record = parsed(runner(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"]),
                    "Protected drain run metadata is invalid")
    require(isinstance(record, dict)
            and type(record.get("id")) is int and record["id"] == run_id
            and isinstance(record.get("repository"), dict)
            and record["repository"].get("full_name") == REPOSITORY
            and record.get("status") == "completed"
            and record.get("conclusion") == "success"
            and record.get("event") == "workflow_dispatch"
            and record.get("head_branch") == "main"
            and record.get("head_sha") == source_commit
            and type(record.get("run_attempt")) is int
            and record["run_attempt"] == 1
            and type(record.get("workflow_id")) is int,
            "Protected drain run is not a successful exact-main observation")
    workflow = parsed(runner(["gh", "api", f"repos/{REPOSITORY}/actions/workflows/"
                              f"{record['workflow_id']}"]),
                      "Protected drain workflow metadata is invalid")
    require(isinstance(workflow, dict) and workflow.get("path") == WORKFLOW
            and workflow.get("state") == "active",
            "Protected drain run used a different workflow")
    completed = record.get("updated_at")
    utc(completed)
    return {"run_id": run_id, "source_commit": source_commit,
            "completed_at_utc": completed}


def verify_attestation(path: Path, source_commit: str,
                       runner: Run = command) -> str:
    output = runner([
        "gh", "attestation", "verify", str(path), "--repo", REPOSITORY,
        "--signer-workflow", SIGNER, "--source-ref", "refs/heads/main",
        "--source-digest", source_commit, "--format", "json",
    ])
    verified = parsed(output, "Protected drain attestation output is invalid")
    require(isinstance(verified, list) and len(verified) == 1
            and isinstance(verified[0], dict)
            and isinstance(verified[0].get("attestation"), dict)
            and isinstance(verified[0].get("verificationResult"), dict),
            "Protected drain artifact needs one verified workflow attestation")
    bundle = json.dumps(verified[0]["attestation"], sort_keys=True,
                        separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(bundle).hexdigest()


def verify_observation(directory: Path, run_id: int, source_commit: str,
                       completed_at_utc: str,
                       attestor: Callable[[Path, str], str] = verify_attestation,
                       ) -> dict[str, Any]:
    require(type(run_id) is int and RUN_ID.fullmatch(str(run_id)) is not None
            and isinstance(source_commit, str)
            and SHA.fullmatch(source_commit) is not None,
            "Protected drain observation identity is invalid")
    names = {
        "installation": f"passport-beta-fence-installation-{run_id}.json",
        "snapshot": f"passport-beta-cutover-snapshot-{run_id}.json",
        "drain": f"passport-beta-predeletion-drain-{run_id}.json",
    }
    require(directory.is_dir() and not directory.is_symlink()
            and {item.name for item in directory.iterdir()} == set(names.values()),
            "Protected drain artifact has missing or extra files")
    paths = {key: directory / name for key, name in names.items()}
    for path in paths.values():
        require(path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= 2 * 1024 * 1024,
                "Protected drain artifact file is missing or oversized")
    installation, installation_sha = read(paths["installation"])
    snapshot, snapshot_sha = read(paths["snapshot"])
    observed, _ = read(paths["drain"])
    expected = collect(installation, snapshot,
                       installation_file_sha256=installation_sha,
                       snapshot_file_sha256=snapshot_sha,
                       source_commit=source_commit)
    require(observed == expected, "Protected drain projection differs from live inputs")
    completed = utc(completed_at_utc)
    require(utc(snapshot.get("observed_at_utc")) <= completed,
            "Protected drain run completed before its snapshot")
    attestations = {key: attestor(path, source_commit)
                    for key, path in paths.items()}
    require(all(isinstance(value, str)
                and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                for value in attestations.values()),
            "Protected drain attestation digest is invalid")
    result = json.loads(json.dumps(expected))
    result["status"] = "verified_observation"
    result["installation"] = json.loads(json.dumps(installation))
    result["snapshot"] = json.loads(json.dumps(snapshot))
    result["observation_run_id"] = run_id
    result["observation_completed_at_utc"] = completed_at_utc
    result["attestation_sha256"] = attestations
    result["probe"]["evidence"]["legacy_source"][
        "drain_snapshot_attestation_sha256"] = attestations["snapshot"]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        run = verify_run(args.run_id, args.source_commit)
        with tempfile.TemporaryDirectory(prefix="passport-predeletion-observation-") as root:
            directory = Path(root)
            command(["gh", "run", "download", str(args.run_id), "--repo", REPOSITORY,
                     "--name", f"passport-beta-predeletion-drain-{args.run_id}",
                     "--dir", str(directory)])
            report = verify_observation(directory, args.run_id,
                                        args.source_commit, run["completed_at_utc"])
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (HostProbeError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Protected beta drain observation unavailable: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
