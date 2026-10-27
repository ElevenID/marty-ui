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
    guide = (
        f"# Marty {candidate['tag']} installation-test nightly\n\n"
        "This experimental Linux amd64 bundle is for disposable installation testing.\n"
        "The nightly runtime happy path and artifact checks do not establish a supported\n"
        "self-host installation or production readiness. Use disposable identities and data.\n\n"
        f"Source: {candidate['source_sha']}\nProducer run: {candidate['build_run_id']}\n\n"
        "To attempt the signed, unqualified candidate through the installer on a\n"
        "disposable Linux amd64 host, run:\n\n"
        f"curl -fsSL https://github.com/ElevenID/marty-ui/releases/download/{candidate['tag']}/install.sh | "
        f"sh -s -- --candidate-test {candidate['tag']} --install-dir /absolute/disposable/path\n\n"
        "This test path does not grant admission or Ready status. Preserve its\n"
        "installation path and redacted diagnostics if it exits nonzero.\n\n"
        "Verify the signed release inventory, then SHA256SUMS before extraction.\n"
        "Use this exact source revision and its docs/selfhost-disposable-qualification-runbook.md.\n"
        "The six preparation assets and SHA256SUMS can be passed unchanged to\n"
        "scripts/stage_selfhost_disposable_preview.py --with-operator-password.\n"
        "Install the matching signed marty-deploy operator before the sudo KMS steps.\n"
        "Record failures and redacted diagnostics; keep credential files private.\n"
    )
    (output / "SELFHOST-PREVIEW-README.md").write_text(guide, encoding="utf-8")
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
