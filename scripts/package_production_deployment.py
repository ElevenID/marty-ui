#!/usr/bin/env python3
"""Bind a production UI to unchanged, authenticated stable OpenBao stack assets.

The producing workflow verifies the stable subjects before invoking this offline
packager, then signs and attests its outputs. This does not deploy an installation
or establish runtime/billing qualification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import tempfile
import zipfile

import yaml

import stable_installer_assets as stable
import ui_release as ui
from record_selfhost_bundle_preparation import extract_owned_zip

SCHEMA = "marty.production-openbao-deployment/v1"
ROOT = Path(__file__).resolve().parents[1]


def inspect_bundle(archive: Path, lock_bytes: bytes) -> str:
    lock = json.loads(lock_bytes)
    with zipfile.ZipFile(archive) as source, tempfile.TemporaryDirectory(prefix="production-bundle-") as tmp:
        extracted = Path(tmp)
        root, files, directories = extract_owned_zip(source, extracted)
        bundle = extracted / root
        ui.require((bundle / ".marty-selfhost-images.json").read_bytes() == lock_bytes,
                   "production backend embedded image lock differs")
        marker = ui.read(bundle / ".marty-selfhost-bundle.json")
        ui.require(marker.get("schema") == "marty.selfhost-bundle-files/v1",
                   "production backend bundle ownership schema differs")
        ui.require(directories == {f"{root}/{name}/" if name else f"{root}/" for name in marker["directories"]}
                   and {name: value for name, value in files.items()
                        if name != f"{root}/.marty-selfhost-bundle.json"}
                   == {f"{root}/{name}": value for name, value in marker["files"].items()},
                   "production backend bundle ownership differs")
        model = yaml.safe_load((bundle / "docker-compose.yml").read_bytes())
        services = model["services"]
        ui.require({name: service.get("image") for name, service in services.items()} == lock["services"]
                   and all("build" not in service for service in services.values()),
                   "production backend Compose image closure differs")
        ui.require("ui" in services, "production backend omits the UI role")
        bao = yaml.safe_load((bundle / "docker-compose.selfhost.openbao.yml").read_bytes())["services"]
        ui.require(set(bao) == {"openbao-tls-init", "openbao", "openbao-unseal", "openbao-bootstrap"}
                   and all(service.get("image") == lock["openbao_didcomm_image"] and "build" not in service
                           for service in bao.values()), "production backend OpenBao image closure differs")
        return root


def compose_override(image: str) -> bytes:
    return ("# Apply after the unchanged, image-locked backend docker-compose.yml.\n"
            "services:\n  ui:\n    image: " + image + "\n"
            "    volumes: !reset []\n"
            "    healthcheck:\n"
            '      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:80/"]\n').encode()


def package(root: Path, ui_manifest: Path, assets: Path, *, source_sha: str,
            tag: str, output: Path) -> dict:
    website = ui.validate_production_release(root, ui.read(ui_manifest), source_sha)
    ui.require(tag == "v" + website["version"], "production UI and stable stack versions differ")
    inventory = stable.read_inventory(assets)
    stable.verify_inputs(assets, source_sha=source_sha, tag=tag,
                         run_id=inventory["build_run_id"], run_attempt=inventory["build_run_attempt"])
    lock_bytes = (assets / "prepared-selfhost-images.json").read_bytes()
    lock = json.loads(lock_bytes)
    bundle_root = inspect_bundle(assets / "prepared-selfhost-bundle.zip", lock_bytes)
    image = website["image"]["uri"] + "@" + website["image"]["digest"]
    overlay = compose_override(image)
    names = (*stable.SUBJECTS, *(name + ".provenance.jsonl" for name in stable.SUBJECTS))
    payloads = {}
    for name in names:
        path = assets / name
        stable.provenance.local_file(path)
        payloads["backend/" + name] = path.read_bytes()
    payloads["production-web-release.json"] = ui_manifest.read_bytes()
    payloads["compose.production-ui.yml"] = overlay
    pages = website.get("production_pages", "public")
    payloads["README.md"] = (
        "# Production website and OpenBao stack\n\n"
        "This package binds a production UI image to the unchanged stable backend assets. "
        "Use a separate Compose deployment; this is not an overlay for an installation owned by the native installer.\n\n"
        "Verify this archive and production-deployment.json against their producing workflow and exact source before use. "
        "The original backend inventory and provenance proofs are retained in backend/.\n\n"
        "Extract the backend bundle, then follow its SELFHOST_BUNDLE.md and SELFHOST_OPENBAO.md "
        "for production secrets, key provisioning, migrations, and one-time OpenBao initialization. "
        "No application AWS KMS or Cloudflare connector is required.\n\n"
        "```sh\nunzip backend/prepared-selfhost-bundle.zip -d stack\n"
        f"cd stack/{bundle_root}\n"
        "# Configure .env.selfhost.production.local and provision its required secrets first.\n"
        "# Use the bundled OpenBao procedure for the separate OpenBao Compose project.\n"
        "docker compose --env-file .env.selfhost.production.local -f docker-compose.yml "
        "-f ../../compose.production-ui.yml config --quiet\n"
        "# After the documented initial provisioning and migrations have completed:\n"
        "docker compose --env-file .env.selfhost.production.local -f docker-compose.yml "
        "-f ../../compose.production-ui.yml up -d --wait\n```\n\n"
        "The production UI retains all pages in its selected build. ORGANIZATION_CREATION_ENABLED "
        "uses the same true/false value in the UI and backend. Its default is false.\n\n"
        + ("This full page build includes the private commerce UI. A compatible billing backend, "
           "database lifecycle, payment configuration, and checkout journey remain unqualified; "
           "the OpenBao application bundle does not supply that retired backend.\n"
           if pages == "full" else
           "This public page build includes marketing, documentation, blog, and legal pages. "
           "It is not the full commerce page build and does not satisfy a request for pricing/checkout pages.\n")
    ).encode()
    manifest = {
        "schema": SCHEMA, "audience": "production", "production_pages": pages,
        "source_sha": source_sha, "release_tag": tag, "platform": "linux/amd64",
        "deployment": "separate-compose", "kms_provider": "openbao",
        "ui_release_sha256": ui.digest(ui_manifest.read_bytes()),
        "backend": {"repository": ui.REPOSITORY, "workflow": stable.WORKFLOW,
                    "run_id": inventory["build_run_id"], "run_attempt": inventory["build_run_attempt"],
                    "inventory_sha256": ui.digest(payloads["backend/installer-inventory.json"]),
                    "bundle_root": bundle_root},
        "images": {**lock["services"], "ui": image},
        "openbao_didcomm_image": lock["openbao_didcomm_image"],
        "qualification": {"runtime_tested": False, "billing_journey_tested": False},
        "files": {name: {"sha256": ui.digest(raw), "bytes": len(raw)}
                  for name, raw in sorted(payloads.items())},
    }
    manifest_bytes = ui.canonical(manifest)
    payloads["production-deployment.json"] = manifest_bytes
    ui.require(not output.exists(), "production package output already exists")
    output.mkdir(parents=True)
    (output / "production-deployment.json").write_bytes(manifest_bytes)
    with zipfile.ZipFile(output / "production-openbao.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(payloads.items()):
            entry = zipfile.ZipInfo("production-openbao/" + name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            executable = name in {"backend/install.sh", "backend/marty-deploy-linux-amd64"}
            entry.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, raw)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    for name in ("ui-release", "backend-assets", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "tag"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    package(args.root, args.ui_release.absolute(), args.backend_assets.absolute(),
            source_sha=args.source_sha, tag=args.tag, output=args.output_dir.absolute())


if __name__ == "__main__":
    main()
