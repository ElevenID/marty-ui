#!/usr/bin/env python3
"""Compose independently authenticated web and unchanged stable OpenBao inputs.

No build, release claim, image mutation or deployment occurs here. The producing
workflow signs/attests both outputs. Every consumer reauthenticates the original
producers as well as that composition producer before applying website routes.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import stat
import tempfile
import zipfile

import yaml

import installer_release as installer
import package_production_deployment as legacy
import stable_installer_assets as stable
import ui_release as ui
import website_provenance as proof
import website_release as web

SCHEMA = "marty.web-composition/v1"
WEBSITE_FILES = ("website-release.json", "website-release.json.sigstore.json",
                 "website-release.json.provenance.jsonl", "image.provenance.jsonl", "web-surface-routes.json")
APPLICATION_FILES = ("production-web-release.json", "production-web-release.json.sigstore.json",
                     "production-web-release.json.provenance.jsonl", "application-web-compatibility.json",
                     "application-web-compatibility.json.sigstore.json", "application-web-compatibility.json.provenance.jsonl",
                     "image.provenance.jsonl")
BACKEND_FILES = (*stable.SUBJECTS, *(name + ".provenance.jsonl" for name in stable.SUBJECTS))
PAYLOAD_NAMES = {f"{prefix}/{name}" for prefix, names in
                 (("website", WEBSITE_FILES), ("application", APPLICATION_FILES), ("backend", BACKEND_FILES)) for name in names}
MAX_ARCHIVE_BYTES = 1024**3
MAX_TOTAL_BYTES = 1024**3
EDGE_INCLUDE = "include /etc/nginx/marty-website/*.conf;"


def copy_inputs(source: Path, names: tuple[str, ...], destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for name in names:
        path = source / name
        maximum = installer.ARTIFACT_MAX_BYTES.get(name, proof.PROOF_LIMIT)
        proof.verifier.local_file(path, maximum=maximum)
        shutil.copyfile(path, destination / name)
        (destination / name).chmod(0o600)


def edge_capability(assets: Path, bundle_root: str) -> None:
    with zipfile.ZipFile(assets / "prepared-selfhost-bundle.zip") as archive:
        try:
            model = yaml.safe_load(archive.read(bundle_root + "/docker-compose.yml"))
            template = archive.read(bundle_root + "/docker/nginx-selfhost.prod.conf.template").decode()
        except (KeyError, ValueError):
            raise ValueError("backend lacks the qualified independent website edge") from None
    edge = model["services"].get("edge", {})
    ui.require(not edge.get("depends_on")
               and "http://127.0.0.1/edge-healthz" in edge.get("healthcheck", {}).get("test", [])
               and EDGE_INCLUDE in template, "backend edge does not support independent website readiness and routes")


def authenticate_payloads(directory: Path, *, gh: Path, cosign: Path,
                          runner: proof.verifier.Run = proof.verifier.command) -> tuple[dict, dict, dict, dict, str]:
    website = proof.verify_website(directory / "website", gh=gh, cosign=cosign, runner=runner)
    application, compatibility = proof.verify_application(directory / "application", gh=gh, cosign=cosign, runner=runner)
    ui.require(website["image_metadata"]["route_contract"] == compatibility["marker"]["route_contract"],
               "website and application routing contracts differ; qualify a compatible application first")
    ui.require(website["production_pages"] == application.get("production_pages", "public"),
               "website and application production page audiences differ")
    assets = directory / "backend"
    tag = "v" + application["version"]
    stable.verify_published(assets, source_sha=application["source_sha"], tag=tag, gh=gh)
    inventory = stable.read_inventory(assets)
    lock_bytes = (assets / "prepared-selfhost-images.json").read_bytes()
    bundle_root = legacy.inspect_bundle(assets / "prepared-selfhost-bundle.zip", lock_bytes)
    edge_capability(assets, bundle_root)
    return website, application, compatibility, inventory, bundle_root


def describe(directory: Path, producer: dict, website: dict, application: dict, compatibility: dict,
             inventory: dict, bundle_root: str) -> dict:
    proof.validate_producer(producer)
    lock = web.read(directory / "backend/prepared-selfhost-images.json")
    app_image = application["image"]["uri"] + "@" + application["image"]["digest"]
    files = {name: {"sha256": proof.file_digest(directory / name), "bytes": (directory / name).stat().st_size}
             for name in sorted(PAYLOAD_NAMES)}
    result = {
        "schema": SCHEMA, "producer": producer, "platform": "linux/amd64", "route_contract": compatibility["marker"]["route_contract"],
        "website": {"revision": website["revision"], "source_sha": website["source_sha"], "image": website["image"],
                    "release_sha256": files["website/website-release.json"]["sha256"], "producer": website["producer"]},
        "application": {"source_sha": application["source_sha"], "image": application["image"],
                        "release_sha256": files["application/production-web-release.json"]["sha256"],
                        "compatibility_sha256": files["application/application-web-compatibility.json"]["sha256"],
                        "producer": compatibility["producer"]},
        "backend": {"source_sha": application["source_sha"], "release_tag": "v" + application["version"],
                    "repository": ui.REPOSITORY, "workflow": stable.WORKFLOW,
                    "run_id": inventory["build_run_id"], "run_attempt": inventory["build_run_attempt"],
                    "inventory_sha256": files["backend/installer-inventory.json"]["sha256"], "bundle_root": bundle_root},
        "images": {**lock["services"], "ui": app_image}, "openbao_didcomm_image": lock["openbao_didcomm_image"],
        "production_pages": website["production_pages"], "kms_provider": "openbao",
        "qualification": {"runtime_tested": False, "billing_journey_tested": False}, "files": files,
    }
    result["composition_id"] = ui.digest(ui.canonical(result))
    return result


def validate_record(record: dict) -> dict:
    fields = {"schema", "producer", "platform", "route_contract", "website", "application", "backend", "images",
              "openbao_didcomm_image", "production_pages", "kms_provider", "qualification", "files", "composition_id"}
    web.object_keys(record, fields, "web composition")
    proof.validate_producer(record["producer"])
    ui.require(record["schema"] == SCHEMA and record["platform"] == "linux/amd64" and record["kms_provider"] == "openbao"
               and record["production_pages"] in {"public", "full"}
               and record["qualification"] == {"runtime_tested": False, "billing_journey_tested": False},
               "unsupported web composition")
    web.validate_route_identity(record["route_contract"])
    web.object_keys(record["files"], PAYLOAD_NAMES, "composition payload inventory")
    total = 0
    for metadata in record["files"].values():
        web.object_keys(metadata, {"sha256", "bytes"}, "payload file")
        web.image_digest(metadata["sha256"])
        ui.require(type(metadata["bytes"]) is int and 0 < metadata["bytes"] <= MAX_TOTAL_BYTES, "invalid payload size")
        total += metadata["bytes"]
    ui.require(total <= MAX_TOTAL_BYTES, "composition payload exceeds size limit")
    body = {key: value for key, value in record.items() if key != "composition_id"}
    ui.require(record["composition_id"] == ui.digest(ui.canonical(body)), "composition identity differs")
    return record


def package(*, website_assets: Path, application_assets: Path, backend_assets: Path, producer: dict,
            output: Path, gh: Path, cosign: Path, runner: proof.verifier.Run = proof.verifier.command) -> dict:
    ui.require(not output.exists(), "web composition output already exists")
    proof.validate_producer(producer)
    with tempfile.TemporaryDirectory(prefix="marty-web-composition-") as temporary:
        held = Path(temporary).resolve()
        for source, names, prefix in ((website_assets, WEBSITE_FILES, "website"),
                                      (application_assets, APPLICATION_FILES, "application"),
                                      (backend_assets, BACKEND_FILES, "backend")):
            copy_inputs(source, names, held / prefix)
        result = describe(held, producer, *authenticate_payloads(held, gh=gh, cosign=cosign, runner=runner))
        validate_record(result)
        encoded = ui.canonical(result)
        output.mkdir(mode=0o700, parents=True)
        (output / "web-composition.json").write_bytes(encoded)
        with zipfile.ZipFile(output / "web-composition.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(PAYLOAD_NAMES | {"web-composition.json"}):
                info = zipfile.ZipInfo("web-composition/" + name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with archive.open(info, "w") as target:
                    if name == "web-composition.json":
                        target.write(encoded)
                    else:
                        with (held / name).open("rb") as source:
                            shutil.copyfileobj(source, target, length=1024 * 1024)
    return result


def extract(archive_path: Path, manifest: dict, destination: Path) -> None:
    """Closed, bounded extraction after authenticating both outer subjects."""
    validate_record(manifest)
    expected = {"web-composition/" + name for name in PAYLOAD_NAMES | {"web-composition.json"}}
    proof.verifier.local_file(archive_path, maximum=MAX_ARCHIVE_BYTES)
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        ui.require(len(members) == len(expected) and {entry.filename for entry in members} == expected,
                   "composition archive member closure differs")
        ui.require(sum(entry.file_size for entry in members) <= MAX_TOTAL_BYTES + proof.JSON_LIMIT,
                   "composition archive exceeds size limit")
        destination.mkdir(mode=0o700)
        for entry in members:
            mode = entry.external_attr >> 16
            ui.require(stat.S_IFMT(mode) in {0, stat.S_IFREG} and not entry.is_dir() and not entry.flag_bits & 1,
                       "composition archive contains non-ordinary file")
            name = entry.filename.removeprefix("web-composition/")
            if name == "web-composition.json":
                ui.require(entry.file_size <= proof.JSON_LIMIT and archive.read(entry) == ui.canonical(manifest),
                           "composition embedded manifest differs")
                continue
            metadata = manifest["files"][name]
            ui.require(entry.file_size == metadata["bytes"], "composition payload size differs")
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o600)
            ui.require(target.stat().st_size == metadata["bytes"] and proof.file_digest(target) == metadata["sha256"],
                       "composition payload digest differs")


@contextmanager
def verified_package(assets: Path, *, gh: Path, cosign: Path,
                     runner: proof.verifier.Run = proof.verifier.command):
    names = ("web-composition.json", "web-composition.zip", "web-composition.json.sigstore.json",
             "web-composition.json.provenance.jsonl", "web-composition.zip.sigstore.json", "web-composition.zip.provenance.jsonl")
    with tempfile.TemporaryDirectory(prefix="marty-verified-web-") as temporary:
        held = Path(temporary).resolve()
        for name in names:
            maximum = MAX_ARCHIVE_BYTES if name == "web-composition.zip" else proof.PROOF_LIMIT
            proof.verifier.local_file(assets / name, maximum=maximum)
            shutil.copyfile(assets / name, held / name)
            (held / name).chmod(0o600)
        manifest = validate_record(proof.read_metadata(held / "web-composition.json"))
        for name in ("web-composition.json", "web-composition.zip"):
            proof.verify_subject(held / name, producer=manifest["producer"], gh=gh, cosign=cosign, runner=runner)
        payload = held / "payload"
        extract(held / "web-composition.zip", manifest, payload)
        expected = describe(payload, manifest["producer"], *authenticate_payloads(payload, gh=gh, cosign=cosign, runner=runner))
        ui.require(manifest == expected, "composition differs from its authenticated inputs")
        yield manifest, payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("website-assets", "application-assets", "backend-assets", "output-dir", "gh", "cosign"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--producer-repository", choices=tuple(web.REPOSITORIES), required=True)
    for name in ("producer-source-sha", "run-id", "run-attempt"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    producer = {"repository": args.producer_repository,
                "workflow": ui.WORKFLOW if args.producer_repository == ui.REPOSITORY else ui.COMMERCE_WORKFLOW,
                "source_sha": args.producer_source_sha, "ref": web.REF, "run_id": args.run_id, "run_attempt": args.run_attempt}
    package(website_assets=args.website_assets.absolute(), application_assets=args.application_assets.absolute(),
            backend_assets=args.backend_assets.absolute(), producer=producer, output=args.output_dir.absolute(),
            gh=args.gh.absolute(), cosign=args.cosign.absolute())


if __name__ == "__main__":
    main()
