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
    """Public release notes for the direct, exact-tag candidate trial."""
    return (
        f"# Marty {candidate['tag']} installation-test nightly\n\n"
        "Try this exact-tag nightly bootstrap on a fresh disposable Linux amd64 VM snapshot,\n"
        "as an ordinary Docker-enabled user with disposable identities and data:\n\n"
        f"bash -o pipefail -c 'curl -fsSL https://github.com/ElevenID/marty-ui/releases/download/{candidate['tag']}/install.sh | "
        f"sh -s -- --candidate-test {candidate['tag']}'\n\n"
        "The installer prints its private random path under your HOME. No edits, source\n"
        "checkout or organization credentials are needed. Bootstrap uses private\n"
        "temporary verification-tool files.\n"
        "The script is fetched over HTTPS and runs before its own bytes can be verified.\n"
        "Inside that script, signed inventory, operator and payload verification occurs\n"
        "before the operator runs. Bash and curl are required for this one-line wrapper.\n"
        "The local rootful Docker socket grants Docker administrator authority; the\n"
        "trial may pull images, create containers, a network and Redis volume,\n"
        "bind a loopback port, and retain private credentials and state. Ordinary uninstall\n"
        "retains data, credentials, images and the volume; purge is unsupported.\n"
        "The direct trial uses your existing Docker Engine and Compose plugin; it does\n"
        "not install OS packages or alter host CA trust. Reset the disposable VM snapshot\n"
        "after collecting feedback. --yes skips only the prompt.\n\n"
        "Exit 0 after required read-only validation means an experimental trial was observed,\n"
        "not production readiness: the journal remains Provisioning, installation_ready\n"
        "is false, and installed-journey qualification is not assessed. A failure may occur\n"
        "after resources are created. Preserve the printed path and first failing stage.\n"
        "Reply to your inviter with the exit status, time, OS/arch, RAM/disk, Docker and\n"
        "Compose versions, prompts/host changes and redacted error output; optionally\n"
        "comment on https://github.com/ElevenID/marty-ui/issues/1350. Do not share\n"
        "secret values, raw credential diagnostics or production data.\n\n"
        f"Source: {candidate['source_sha']}\nProducer run: {candidate['build_run_id']}\n\n"
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
