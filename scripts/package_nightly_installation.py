#!/usr/bin/env python3
"""Prepare an exact image-locked ZIP for disposable nightly installation tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from nightly_release import base_version, image_lock, pin_external_images, read, validate_candidate
from produce_selfhost_product_descriptor import produce
from record_selfhost_bundle_preparation import record
from stage_selfhost_disposable_preview import ASSETS


def write(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def nightly_trial_guide(candidate: dict) -> str:
    """Describe only the experimental root-free candidate path in this source."""
    tag = candidate["tag"]
    return (
        f"# Marty {tag} experimental root-free candidate\n\n"
        "This exact candidate attempts a rootless storage ownership canary and then\n"
        "stack provisioning with required read-only validation. It can fail at any stage;\n"
        "it grants neither installer admission nor production Ready status. The live\n"
        "rootless canary still requires qualification before this command is advertised\n"
        "to outside testers. Normal admitted installation remains held.\n\n"
        "On a disposable Linux amd64 VM with a pre-existing user-owned rootless daemon:\n\n"
        f"/usr/bin/setpriv --no-new-privs -- bash -o pipefail -c 'curl -fsSL "
        f"https://github.com/ElevenID/marty-ui/releases/download/{tag}/install.sh | "
        f"sh -s -- --candidate-test {tag}'\n\n"
        "Trusted setpriv, Bash, curl, Docker client and Compose are prerequisites. The\n"
        "entire pipeline inherits no-new-privileges; a failed download is nonzero.\n"
        "No source checkout, organization credentials, edited installation path or\n"
        "separate download package is needed. The installer never uses sudo, installs\n"
        "OS packages, starts a daemon, or falls back to a rootful socket. It uses\n"
        "private temporary verification-tool and Docker-config files.\n\n"
        "The initial HTTPS script executes before its own bytes are independently\n"
        "verified. It authenticates signed inventory and operator before operator\n"
        "execution. The operator can write private state/evidence before it verifies\n"
        "remaining payloads; payload checks precede Docker runtime provisioning.\n"
        "The canary records an exact image pull intent before acquisition, tests a\n"
        "reversible rootless ownership transition, and stops on uncertainty. It may\n"
        "pull images, create exact helper containers, and retain state/data; ordinary\n"
        "uninstall retains credentials, images and the Redis volume. No auto-purge.\n\n"
        "For an interrupted foreign-owned canary, preserve the installation and use\n"
        "the retained operator's recovery-only command after checking both absolute\n"
        "paths (the Docker path below is an example):\n\n"
        "Recovery only: /usr/bin/setpriv --no-new-privs -- /absolute/retained/installation/marty-deploy "
        "restore-rootless-canary --installation /absolute/retained/installation "
        "--docker-bin /usr/bin/docker\n\n"
        "Recovery does not resume provisioning or grant Ready. A consumed one-shot\n"
        "retry may require manual review. Reset the disposable VM after feedback.\n\n"
        "Send the first error and exit status, OS/architecture, RAM/disk and Docker/\n"
        "Compose versions to your inviter or https://github.com/ElevenID/marty-ui/issues/1350.\n"
        "Use disposable data; keep secret values and raw credential diagnostics private.\n\n"
        f"Source: {candidate['source_sha']}\nProducer run: {candidate['build_run_id']}\n"
    )


def package(source: Path, candidate_path: Path, packager: Path, output: Path,
            compose_executable: Path | None = None) -> None:
    source = source.resolve(strict=True)
    candidate = validate_candidate(read(candidate_path))
    if output.exists() or not output.is_absolute() or output.resolve().is_relative_to(source):
        raise ValueError("nightly package output must be fresh and outside source")
    output.mkdir(mode=0o700)
    keycloak = candidate["images"]["keycloak"]
    environment = {**os.environ, "SELFHOST_IMAGE_PREFIX": "ghcr.io/elevenid/marty-ui",
        "SELFHOST_IMAGE_TAG": base_version(candidate["tag"]),
        "MARTY_KEYCLOAK_KMS_IMAGE": keycloak["uri"] + "@" + keycloak["digest"]}
    rendered = subprocess.run(["docker", "compose", "--profile", "*", "--env-file",
        ".env.selfhost.production.example", "-f", "docker-compose.selfhost.prod.yml",
        "-f", "docker-compose.selfhost.bundle.override.yml", "config", "--format", "json"],
        cwd=source, env=environment, check=True, capture_output=True, text=True, timeout=60)
    model = json.loads(rendered.stdout)
    external = pin_external_images(model, source)
    locked = image_lock(candidate, model, source, external)
    lock_path = output / "prepared-selfhost-images.json"
    write(lock_path, locked)
    transaction = output / "selfhost-preparation-transaction.json"
    write(transaction, candidate)
    compose_args = (["--compose-executable", str(compose_executable)]
                    if compose_executable else [])
    subprocess.run([str(packager), "--repo-root", str(source), "--output-dir",
        str(output / "selfhost-prepared"), "--archive", str(output / "prepared-selfhost-bundle"),
        "--image-lock", str(lock_path), "--nightly-candidate", str(transaction), *compose_args],
        check=True, cwd=source, timeout=180)
    archive = output / "prepared-selfhost-bundle.zip"
    receipt = output / "prepared-selfhost-bundle.json"
    write(receipt, record(archive, lock_path, transaction, candidate["source_sha"], candidate["build_run_id"]))
    write(output / "prepared-selfhost-product-descriptor.json", produce(archive, lock_path, transaction, receipt))
    (output / "SELFHOST-PREVIEW-README.md").write_text(
        nightly_trial_guide(candidate), encoding="utf-8")
    with (output / "SHA256SUMS").open("x", encoding="ascii") as stream:
        for name in sorted(ASSETS):
            stream.write(hashlib.sha256((output / name).read_bytes()).hexdigest() + "  " + name + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "candidate", "packager", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--compose-executable", type=Path)
    args = parser.parse_args()
    package(args.source, args.candidate, args.packager, args.output, args.compose_executable)


if __name__ == "__main__":
    main()
