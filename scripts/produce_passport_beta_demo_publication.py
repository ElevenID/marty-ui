#!/usr/bin/env python3
"""Produce a protected D-12 receipt from one signed beta and reviewed recording."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

if __package__:
    from .collect_passport_beta_acceptance import (
        production_attachment_commitment,
        production_snapshot_commitment,
        verify_attestations,
    )
    from .collect_passport_beta_aggregate_acceptance import collect_aggregate
    from .probe_passport_beta_host import (
        assert_production_unchanged,
        production_attachment_sha256,
        production_snapshot,
    )
    from .read_protected_passport_artifact import read_artifact
else:
    from collect_passport_beta_acceptance import (
        production_attachment_commitment,
        production_snapshot_commitment,
        verify_attestations,
    )
    from collect_passport_beta_aggregate_acceptance import collect_aggregate
    from probe_passport_beta_host import (
        assert_production_unchanged,
        production_attachment_sha256,
        production_snapshot,
    )
    from read_protected_passport_artifact import read_artifact


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NEGATIVE = (
    "unsigned-callback-uncut.webm",
    "unsigned-callback-privacy-scan.json",
    "foreign-callback-uncut.webm",
    "foreign-callback-privacy-scan.json",
)
DEPLOYMENT = (
    "aggregate_deployment_receipt_sha256",
    "aggregate_plan_sha256",
    "production_snapshot_commitment",
    "production_attachment_commitment",
)
PRODUCER_FIELDS = (
    "beta_origin",
    "physical_claim",
    "booklet_verified",
    "release",
    "deployment",
    "preliminary",
    "selected_source_job_commitment",
    "selected_bureau_job_commitment",
    "media",
    "youtube",
)
DEPLOY_SCRIPT = "scripts/deploy-passport-demo-content-beta.ps1"


class PublicationEvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationEvidenceError(message)


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def require_beta_deploy_config(path: Path) -> None:
    """Accept only reviewed commands with no production mutation hook."""
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PublicationEvidenceError("Reviewed D-12 publication config is invalid") from exc
    automation = config.get("automation") if isinstance(config, dict) else None
    require(isinstance(automation, dict)
            and set(automation) == {
                "record", "prePublicBuild", "deploy", "rollbackDeploy", "smoke",
            },
            "D-12 beta deployment commands are missing or unrestricted")
    require(
        automation["record"] == {
            "command": "node", "args": ["-e", "process.exit(1)"], "cwd": ".",
        },
        "D-12 record hook must reject missing reviewed video",
    )
    require(
        automation["prePublicBuild"] == {
            "command": "node", "args": ["-e", "process.exit(0)"], "cwd": ".",
        },
        "D-12 pre-public build hook must be inert",
    )
    for name, mode in (("deploy", "Deploy"), ("rollbackDeploy", "Rollback")):
        spec = automation.get(name)
        require(
            isinstance(spec, dict)
            and spec.get("command") == "powershell.exe"
            and spec.get("args")
            == [
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                DEPLOY_SCRIPT, "-Mode", mode,
            ]
            and spec.get("cwd", ".") == ".",
            f"D-12 {name} must use the reviewed beta-only deployment wrapper",
        )
    require(
        automation["smoke"] == {
            "command": "node",
            "args": ["tests/scripts/smoke-beta-demo-publication.js"],
            "cwd": ".",
        },
        "D-12 smoke must use the reviewed beta-only browser check",
    )


def run(*args: str, timeout: int = 180) -> str:
    try:
        return subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=timeout
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicationEvidenceError("Protected publication command failed") from exc


def public_http() -> None:
    request = urllib.request.Request(
        "https://elevenidllc.com/", headers={"User-Agent": "MartyPassportBeta/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            require(
                response.status == 200
                and response.geturl() == "https://elevenidllc.com/",
                "Production public site did not return HTTP 200 at its canonical URL",
            )
    except (OSError, ValueError) as exc:
        raise PublicationEvidenceError("Production public site is unavailable") from exc


def expected_from_live_preliminary(
    live: dict[str, Any],
    preliminary: dict[str, Any],
    source: str,
) -> dict[str, Any]:
    """Freeze only the final consumer's release, selected-job and media identity."""
    require(
        SHA.fullmatch(source) is not None
        and live.get("schema") == "marty.passport-beta-acceptance/v1"
        and live.get("status") == "blocked"
        and live.get("beta_origin") == "https://beta.elevenidllc.com"
        and live.get("physical_claim") == "not_claimed"
        and isinstance(live.get("release"), dict)
        and live["release"].get("signed_manifest_verified") is True
        and live["release"].get("source_commit") == source
        and SHA256.fullmatch(live["release"].get("stack_manifest_sha256", ""))
        and isinstance(live.get("deployment"), dict)
        and live["deployment"].get("provider_mode") == "simulator"
        and all(
            SHA256.fullmatch(live["deployment"].get(name, "")) for name in DEPLOYMENT
        ),
        "Live signed aggregate simulator beta is unavailable",
    )
    require(
        preliminary.get("kind") == "preliminary"
        and type(preliminary.get("run_id")) is int
        and preliminary["run_id"] > 0
        and preliminary.get("workflow_commit") == source
        and SHA256.fullmatch(preliminary.get("artifact_sha256", ""))
        and isinstance(preliminary.get("value"), dict),
        "Protected preliminary artifact differs from this main revision",
    )
    value = preliminary["value"]
    release = {
        name: live["release"][name]
        for name in ("source_commit", "stack_manifest_sha256")
    }
    deployment = {name: live["deployment"][name] for name in DEPLOYMENT}
    require(
        value.get("schema") == "marty.passport-beta-preliminary/v1"
        and value.get("status") == "qualified_for_recording"
        and value.get("beta_origin") == live["beta_origin"]
        and value.get("physical_claim") == "not_claimed"
        and value.get("synthetic_identities_only") is True
        and isinstance(value.get("release"), dict)
        and value["release"].get("signed_manifest_verified") is True
        and all(value["release"].get(name) == release[name] for name in release)
        and isinstance(value.get("deployment"), dict)
        and value["deployment"].get("provider_mode") == "simulator"
        and all(
            value["deployment"].get(name) == deployment[name] for name in DEPLOYMENT[:2]
        ),
        "Preliminary recording differs from the signed aggregate beta",
    )
    media = preliminary.get("media_sha256")
    require(
        isinstance(media, dict)
        and set(media) == set(NEGATIVE)
        and all(SHA256.fullmatch(media[name]) for name in NEGATIVE)
        and media[NEGATIVE[0]] != media[NEGATIVE[2]],
        "Protected preliminary negative media is incomplete",
    )
    probes = value.get("probes")
    selected = (
        probes.get("nine_route_gateway_flow") if isinstance(probes, dict) else None
    )
    evidence = selected.get("evidence") if isinstance(selected, dict) else None
    source_job = (
        evidence.get("source_job_commitment") if isinstance(evidence, dict) else None
    )
    bureau_job = (
        evidence.get("bureau_job_commitment") if isinstance(evidence, dict) else None
    )
    require(
        selected.get("verified") is True if isinstance(selected, dict) else False,
        "Preliminary selected Flow is unverified",
    )
    require(
        isinstance(source_job, str)
        and SHA256.fullmatch(source_job)
        and isinstance(bureau_job, str)
        and SHA256.fullmatch(bureau_job),
        "Preliminary selected job commitments are incomplete",
    )
    return {
        "release": release,
        "deployment": deployment,
        "preliminary": {
            "run_id": preliminary["run_id"],
            "artifact_sha256": preliminary["artifact_sha256"],
            "negative_media_sha256": media,
        },
        "selected_source_job_commitment": source_job,
        "selected_bureau_job_commitment": bureau_job,
    }


def stage_negative_media(
    stage: Path,
    video_dir: Path,
    hashes: dict[str, str],
    copied: list[Path],
) -> None:
    """Use reviewed originals when exact, otherwise add temporary protected copies."""
    for name in NEGATIVE:
        original = stage / name
        target = video_dir / name
        require(
            original.is_file()
            and not original.is_symlink()
            and digest(original) == hashes[name]
            and not target.is_symlink(),
            "Protected preliminary media is unavailable or altered",
        )
        if target.exists():
            require(
                target.is_file() and digest(target) == hashes[name],
                "Reviewed negative media differs from the protected run",
            )
        else:
            with original.open("rb") as source_file, target.open("xb") as target_file:
                shutil.copyfileobj(source_file, target_file)
            copied.append(target)


def produce(args: argparse.Namespace) -> None:
    require(
        args.output.parent.is_dir()
        and not args.output.exists()
        and not args.output.is_symlink(),
        "Protected publication output path is invalid",
    )
    require(
        args.artifact_dir.is_dir()
        and args.config.is_file()
        and args.video.is_file()
        and args.campaign.is_file(),
        "Signed beta or reviewed recording inputs are unavailable",
    )
    require(Path.cwd().resolve() == Path(__file__).resolve().parents[1],
            "D-12 beta deployment requires the reviewed UI checkout")
    require_beta_deploy_config(args.config)
    require(
        args.recorder_root.is_dir()
        and SHA.fullmatch(args.recorder_commit) is not None
        and run("git", "-C", str(args.recorder_root), "rev-parse", "HEAD")
        == args.recorder_commit
        and not run("git", "-C", str(args.recorder_root), "status", "--porcelain"),
        "Pinned recorder checkout is unavailable or dirty",
    )
    source = os.environ.get("GITHUB_SHA", "")
    api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY", "")
    require(
        SHA.fullmatch(source) is not None
        and len(api_key) >= 32
        and not any(c in api_key for c in "\r\n\0")
        and run("git", "rev-parse", "HEAD") == source,
        "Protected main source or organization key is unavailable",
    )
    before = production_snapshot()
    attachment_before = production_attachment_sha256()
    public_http()
    try:
        live = collect_aggregate(
            args.artifact_dir, api_key=api_key, attest=verify_attestations
        )
        preliminary = read_artifact("preliminary", args.preliminary_run_id)
        expected = expected_from_live_preliminary(live, preliminary, source)
        receipt = json.loads(
            (args.artifact_dir / "aggregate-deployment.json").read_text()
        )
        plan = json.loads(
            (args.artifact_dir / "aggregate-deployment.json.plan.json").read_text()
        )
        require(
            production_snapshot_commitment(api_key, before["sha256"])
            == expected["deployment"]["production_snapshot_commitment"]
            and production_attachment_commitment(api_key, attachment_before)
            == expected["deployment"]["production_attachment_commitment"]
            and before["sha256"] == receipt.get("production_snapshot_sha256")
            and attachment_before == plan.get("production_attachments_sha256"),
            "Live production differs from the aggregate deployment baseline",
        )
        with tempfile.TemporaryDirectory(prefix="marty-passport-d12-") as temporary:
            stage = Path(temporary)
            run(
                "gh",
                "run",
                "download",
                str(args.preliminary_run_id),
                "--repo",
                "ElevenID/marty-ui",
                "--name",
                f"passport-beta-preliminary-{args.preliminary_run_id}",
                "--dir",
                str(stage),
            )
            require(
                {path.name for path in stage.iterdir()}
                == {
                    f"passport-beta-preliminary-{args.preliminary_run_id}.json",
                    *NEGATIVE,
                },
                "Downloaded preliminary artifact shape changed",
            )
            copied = []
            try:
                stage_negative_media(
                    stage, args.video.parent, preliminary["media_sha256"], copied
                )
                expectation = stage / "expected.json"
                expectation.write_text(json.dumps(expected, sort_keys=True))
                provisional = stage / "producer.json"
                run(
                    "node",
                    str(args.recorder_root / "src" / "passportPublicationEvidence.js"),
                    "--config",
                    str(args.config),
                    "--video",
                    str(args.video),
                    "--campaign",
                    str(args.campaign),
                    "--expected",
                    str(expectation),
                    "--output",
                    str(provisional),
                    timeout=15 * 60,
                )
                producer = json.loads(provisional.read_text())
                require(
                    producer.get("schema")
                    == "marty.passport-beta-demo-publication-evidence/v1"
                    and producer.get("status") == "verified"
                    and set(producer) == {"schema", "status", *PRODUCER_FIELDS},
                    "Reviewed recorder did not verify D-12 publication",
                )
                final = {
                    "schema": "marty.passport-beta-demo-publication/v1",
                    "status": "public_verified",
                    "protected_run": {
                        "run_id": os.environ["GITHUB_RUN_ID"],
                        "workflow_commit": source,
                    },
                    **{name: producer[name] for name in PRODUCER_FIELDS},
                }
                require(
                    producer["preliminary"]
                    == {
                        "run_id": expected["preliminary"]["run_id"],
                        "artifact_sha256": expected["preliminary"]["artifact_sha256"],
                    },
                    "Recorder preliminary identity differs from protected run",
                )
            finally:
                for target in copied:
                    target.unlink()
    finally:
        after = production_snapshot()
        attachment_after = production_attachment_sha256()
        public_http()
        assert_production_unchanged(before, after)
        require(
            attachment_before == attachment_after,
            "Production network attachments changed during D-12 publication",
        )
    with args.output.open("x", encoding="utf-8") as target:
        os.chmod(args.output, 0o600)
        json.dump(final, target, indent=2, sort_keys=True)
        target.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "artifact-dir",
        "config",
        "video",
        "campaign",
        "recorder-root",
        "output",
    ):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--preliminary-run-id", required=True, type=int)
    parser.add_argument("--recorder-commit", required=True)
    args = parser.parse_args()
    require(args.preliminary_run_id > 0, "Preliminary run ID is invalid")
    require(
        not args.output.is_symlink(), "Protected publication output path is invalid"
    )
    produce(
        argparse.Namespace(
            **{
                key: value.absolute() if isinstance(value, Path) else value
                for key, value in vars(args).items()
            }
        )
    )


if __name__ == "__main__":
    main()
