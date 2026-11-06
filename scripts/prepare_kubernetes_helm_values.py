#!/usr/bin/env python3
"""Project authenticated installer images into Kubernetes development values.

The complete prepared installer inputs and their Sigstore/SLSA sidecars must be
in a private, caller-owned directory, with no concurrent writer. Runtime source,
tag and producer invocation are independent required inputs, never inferred from
an unverified record. The existing installer validators and pinned verifiers
authenticate the same bytes before either output is written.

Outputs are JSON (accepted by Helm as values): --output for the Marty chart and
--openbao-output for the official OpenBao chart. Both paths must be new files in
private directories. Preserve any partial output on failure. The OpenBao chart
0.30.6 requires registry/repository:tag, so its override uses tag@sha256; the digest
is unchanged. The installer UI is ui-selfhost, not the separate ui image.

This performs no deployment, artifact execution, admission, candidate dispatch,
or Kubernetes qualification. Chart source is separate caller-supplied metadata;
runtime signatures do not authenticate the chart. Retain the original evidence
and perform the target's admission/acceptance steps before runtime mutation.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re

from build_selfhost_image_lock import DEDICATED_SERVICES, KEYCLOAK_SERVICES, SELFHOST_URIS
import installer_release as release
from installer_candidate_authorize import read_record, write_exclusive
# These shared helpers only inspect files and pins. No controller or dispatch
# operation is called by this projection.
from installer_candidate_dispatch import SUBJECTS, SUFFIXES, TOOLS, private_file
from release_transaction import IMAGE_URIS
import verify_installer_provenance as provenance


ROLE_INPUTS = {
    "ui": "ui",
    "services": "gateway",
    "migrations": "db-migrate",
    "keycloak": "keycloak",
    "openbao_didcomm": "openbao_didcomm_image",
}
UPSTREAM_IMAGES = {
    "postgres": "docker.io/library/postgres",
    "redis": "docker.io/library/redis",
}
RECORD_LIMIT = 65536
PROOF_LIMIT = 4 * 1024 * 1024


def _images(inventory: dict) -> dict[str, str]:
    """Internal projection of the already bound installer service image map."""
    selected = inventory["images"]
    repositories = {**IMAGE_URIS, "ui": SELFHOST_URIS["ui-selfhost"]}
    images = {}
    for role, name in ROLE_INPUTS.items():
        reference = selected.get(name)
        release.require(isinstance(reference, str) and re.fullmatch(
            re.escape(repositories[role]) + r"@sha256:[0-9a-f]{64}", reference) is not None,
            f"installer image role {role} is missing or has a different repository")
        images[role] = reference
    release.require(len({image.split("@", 1)[1] for image in images.values()}) == len(images),
                    "installer image role digests are not distinct")
    # Preserve aliases that the native installer relies on. The Helm chart uses
    # one shared services image and one Keycloak image, including its jobs.
    for service in ("gateway", "issuance", "issuance-native", "issuance-migrations", "signing-keys"):
        release.require(selected.get(service) == images["services"],
                        "native service and issuance image bindings differ")
    for service in KEYCLOAK_SERVICES:
        release.require(selected.get(service) == images["keycloak"],
                        "Keycloak configurator image binding differs")
    for service, role in DEDICATED_SERVICES.items():
        release.require(selected.get(service) == images["ui" if role == "ui-selfhost" else "migrations"],
                        "dedicated installer image binding differs")
    # Reject a split digest elsewhere in the signed service map instead of
    # silently collapsing it to the gateway's selected image.
    by_repository = {image.split("@", 1)[0]: image for image in images.values()}
    for image in selected.values():
        repository = image.split("@", 1)[0]
        release.require(repository not in by_repository or image == by_repository[repository],
                        "installer aliases contain different image digests")
    return images


def prepare(*, assets: Path, runtime_source_sha: str, release_tag: str,
            build_run_id: int, build_run_attempt: int, chart_source_sha: str,
            gh: Path, cosign: Path, output: Path, openbao_output: Path,
            runner=provenance.command) -> tuple[dict, dict]:
    """Authenticate the existing installer artifact closure, then project it.

    There is deliberately no unsigned/preverified JSON entry point. ``runner``
    is the shared verifier subprocess boundary used by orchestration unit tests;
    the CLI always uses the real pinned executables.
    """
    release.require(os.name == "posix", "Linux private-file handling is required")
    release.identity(runtime_source_sha, release_tag, build_run_id, build_run_attempt)
    release.sha(chart_source_sha)
    release.require(output != openbao_output, "Helm values outputs must be different files")
    for path in (output, openbao_output):
        release.require(path.is_absolute() and ".." not in path.parts,
                        "absolute Helm values output paths are required")
        release.require(not path.exists() and not path.is_symlink(), "Helm values output already exists")

    # Reuse the same bounded, single-link, caller-private file checks and verifier
    # executable trust anchors as the installer candidate transport.
    observed = {}
    for name in SUBJECTS:
        for suffix in SUFFIXES:
            maximum = (PROOF_LIMIT if suffix else RECORD_LIMIT if name == "installer-inventory.json"
                       else release.ARTIFACT_MAX_BYTES[name])
            path = assets / (name + suffix)
            observed[path] = private_file(path, maximum)
    for name, path in (("gh", gh), ("cosign", cosign)):
        actual = private_file(path, TOOLS[name][1], executable=True)
        release.require(actual == TOOLS[name], "verifier trust anchor differs")
        observed[path] = actual

    expected = dict(source_sha=runtime_source_sha, release_tag=release_tag,
                    build_run_id=build_run_id, build_run_attempt=build_run_attempt)
    inventory_bytes = read_record(assets / "installer-inventory.json")
    inventory = release.verify_inventory_assets(assets, **expected)
    images = _images(inventory)
    upstream = {}
    for service, repository in UPSTREAM_IMAGES.items():
        reference = inventory["images"].get(service)
        release.require(isinstance(reference, str) and re.fullmatch(
            re.escape(repository) + r"@sha256:[0-9a-f]{64}", reference) is not None,
            f"installer infrastructure image {service} is missing or has a different repository")
        upstream[service] = {"image": reference}
    tier, _ = release.classify_release_tag(release_tag)
    workflow = ".github/workflows/nightly-release.yml" if tier == "nightly" else ".github/workflows/cd.yml"
    for name in SUBJECTS:
        provenance.verify_subject(assets / name, assets / (name + ".provenance.jsonl"),
            gh=gh, cosign=cosign, signature_bundle=assets / (name + ".sigstore.json"),
            workflow=workflow, source_sha=runtime_source_sha,
            run_id=build_run_id, run_attempt=build_run_attempt, runner=runner)

    release.require(release.verify_inventory_assets(assets, **expected) == inventory,
                    "installer inputs changed during verification")
    for path, before in observed.items():
        release.require(private_file(path, before[1], executable=path in (gh, cosign)) == before,
                        "verified installer evidence or tool changed")
    release.require(read_record(assets / "installer-inventory.json") == inventory_bytes,
                    "verified installer inventory changed")

    values = {
        "images": images,
        **upstream,
        "release": {
            "runtimeSourceSha": runtime_source_sha,
            "chartSourceSha": chart_source_sha,
            "tag": release_tag,
            "buildRunId": build_run_id,
            "buildRunAttempt": build_run_attempt,
            "inventorySha256": release.digest(inventory_bytes),
            "imageLockSha256": next(entry["sha256"] for entry in inventory["artifacts"]
                                    if entry["name"] == "prepared-selfhost-images.json"),
            "operatorSha256": next(entry["sha256"] for entry in inventory["artifacts"]
                                   if entry["name"] == "marty-deploy-linux-amd64"),
        },
    }
    repository, digest = images["openbao_didcomm"].split("@", 1)
    registry, repository = repository.split("/", 1)
    openbao_values = {"server": {"image": {
        "registry": registry,
        "repository": repository,
        # Upstream 0.30.6 inserts a colon unconditionally. An OCI tag@digest
        # reference retains the exact authenticated digest; the tag is only
        # descriptive (the current signed Marty plugin uses OpenBao 2.5.5).
        "tag": "2.5.5@" + digest,
        "pullPolicy": "IfNotPresent",
    }}}
    write_exclusive(output, release.encode(values))
    write_exclusive(openbao_output, release.encode(openbao_values))
    return values, openbao_values


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assets", "gh", "cosign", "output", "openbao-output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("runtime-source-sha", "chart-source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    try:
        prepare(**vars(parser.parse_args(argv)))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Kubernetes Helm values refused: {error}. Preserve any partial output.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
