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

# Match the native bundle renderer's host-discovery environment. Application,
# Compose and proxy settings belong to the exact package inputs, not the shell
# that happens to invoke this producer.
RENDERER_ENVIRONMENT = (
    "PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
)


def write(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def nightly_trial_guide(candidate: dict) -> str:
    """Describe only the experimental root-free candidate path in this source."""
    tag = candidate["tag"]
    source = candidate["source_sha"]
    guide_url = (
        "https://github.com/ElevenID/marty-ui/blob/"
        f"{source}/docs/linux-installer-tester.md"
    )
    return (
        f"# Marty {tag} experimental root-free candidate\n\n"
        "This exact candidate attempts a rootless storage ownership canary and then\n"
        "stack provisioning with required read-only validation. It can fail at any stage;\n"
        "it grants neither installer admission nor production Ready status. This is an\n"
        "opt-in tester path. Normal admitted installation remains held; do not substitute\n"
        "--channel nightly or --version for the exact candidate selector below.\n\n"
        f"Start with the Linux tester guide for this exact source: {guide_url}\n\n"
        "Use a disposable Linux amd64 system as a regular user with a pre-existing\n"
        "user-owned rootless Docker daemon. The tested target has 8 GiB RAM; reserve\n"
        "at least 20 GiB free on Docker's data filesystem. This is not a production\n"
        "capacity claim. Host preparation is separate from the installer.\n\n"
        "Run this exact release command in a terminal:\n\n"
        f"/usr/bin/setpriv --no-new-privs -- bash -o pipefail -c 'curl -fsSL "
        f"https://github.com/ElevenID/marty-ui/releases/download/{tag}/install.sh | "
        f"sh -s -- --candidate-test {tag}'\n\n"
        "Trusted setpriv, Bash, curl, Docker client and Compose are prerequisites. The\n"
        "entire pipeline inherits no-new-privileges; a failed download is nonzero.\n"
        "No source checkout, organization credentials, edited installation path or\n"
        "separate download package is needed. The installer never uses sudo, installs\n"
        "OS packages, starts a daemon, or falls back to a rootful socket. It uses\n"
        "private temporary verification-tool and Docker-config files.\n\n"
        "Managed OpenBao and private localhost HTTPS are the defaults. Direct public\n"
        "hosting is optional and needs the guide's hosting file, DNS/firewall setup and,\n"
        "for Let's Encrypt, HTTP-01 routing and the tester's agreement to its terms.\n\n"
        "Keep the printed installation path. CANDIDATE TRIAL OBSERVED means startup\n"
        "and required read-only checks passed; it does not qualify login or a credential\n"
        "journey. An ACME enrollment_pending result with application_started=false is\n"
        "not completed startup, even when the command exits zero. Inspect its polling\n"
        "deadline and use only the reported retained continuation; never rerun the\n"
        "initial installer to resume an order. Review or uncertain outcomes require\n"
        "diagnosis before further action.\n\n"
        "Follow the guide to inspect status, doctor, validate and trust-info, verify\n"
        "the browser-facing origin and establish local CA trust when needed. The\n"
        "installer exports paused lifecycle units; follow their returned prerequisite\n"
        "and enablement instructions for unattended recovery before testing a reboot.\n\n"
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
    # Resolve explicit tools in the caller's directory once, before changing
    # cwd for either render. Both stages must use the same selected renderer.
    packager = packager.resolve(strict=True)
    if compose_executable is not None:
        compose_executable = compose_executable.resolve(strict=True)
    if not packager.is_file() or compose_executable is not None and not compose_executable.is_file():
        raise ValueError("nightly package tools must be regular files")
    output.mkdir(mode=0o700)
    keycloak = candidate["images"]["keycloak"]
    environment = {key: os.environ[key] for key in RENDERER_ENVIRONMENT if key in os.environ}
    environment.update({"SELFHOST_IMAGE_PREFIX": "ghcr.io/elevenid/marty-ui",
        "SELFHOST_IMAGE_TAG": base_version(candidate["tag"]),
        "MARTY_KEYCLOAK_KMS_IMAGE": keycloak["uri"] + "@" + keycloak["digest"]})
    renderer = [str(compose_executable)] if compose_executable is not None else ["docker", "compose"]
    rendered = subprocess.run([*renderer, "--profile", "*", "--env-file",
        ".env.selfhost.production.example", "-f", "docker-compose.selfhost.prod.yml",
        "-f", "docker-compose.selfhost.bundle.override.yml", "config", "--format", "json"],
        cwd=source, env=environment, stdin=subprocess.DEVNULL,
        check=True, capture_output=True, text=True, timeout=60)
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
    parser.add_argument("--compose-executable", type=Path,
                        help="Standalone Compose renderer for both image-lock and bundle rendering")
    args = parser.parse_args()
    package(args.source, args.candidate, args.packager, args.output, args.compose_executable)


if __name__ == "__main__":
    main()
