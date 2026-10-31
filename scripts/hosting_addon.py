#!/usr/bin/env python3
"""Package an optional hosting connector from exact source and image evidence.

The output is unsigned until the existing release workflow signs and attests it.
This module does not deploy, read tunnel credentials, or relax core image locks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path

import yaml

from build_selfhost_image_lock import _verify_source_files
from installer_release import classify_release_tag, decode, encode, identity, positive, require
from product_package_plan import runtime_payload

SCHEMA = "elevenid.hosting-addon/v1"
ADDON = "cloudflare-tunnel"
POLICY = "release/hosting-addons.json"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/cloudflared-wrapper"
ARCHIVE = "selfhost-cloudflare-addon.zip"
MANIFEST = "selfhost-cloudflare-images.json"
SBOM = "cloudflared_wrapper.sbom.cdx.json"
ASSETS = (ARCHIVE, MANIFEST, SBOM)
FILES = frozenset({"compose.cloudflare.yml", "scripts/cloudflared-selfhost.sh"})
MAX_ARCHIVE = 1024 * 1024
MAX_PAYLOAD = 512 * 1024


def build_workflow(tag: str) -> str:
    tier, _ = classify_release_tag(tag)
    return {"stable": ".github/workflows/cd.yml", "nightly": ".github/workflows/nightly-release.yml"}[tier]


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def policy(source: Path) -> dict:
    value = decode((source / POLICY).read_bytes())
    require(set(value) == {"schema", "addons"}
            and value["schema"] == "elevenid.hosting-addons/v1"
            and isinstance(value["addons"], dict) and set(value["addons"]) == {ADDON},
            "hosting add-on policy differs")
    item = value["addons"][ADDON]
    require(item == {
        "platform": "linux/amd64", "image": IMAGE,
        "dockerfile": "docker/cloudflared-wrapper.Dockerfile",
        "compose_source": "deploy-config/compose/selfhost-cloudflare/compose.cloudflare.yml",
        "compose_entry": "compose.cloudflare.yml",
        "source_files": {"scripts/cloudflared-selfhost.sh": "scripts/cloudflared-selfhost.sh"},
        "assets": list(ASSETS),
    }, "unreviewed hosting add-on role or asset")
    return item


def validate_manifest(value: dict) -> dict:
    require(set(value) == {"schema", "addon", "platform", "source_sha", "release_tag",
            "build_run_id", "build_run_attempt", "signer_workflow", "services", "files",
            "archive_sha256", "archive_size_bytes", "sbom_sha256"},
            "hosting add-on fields differ")
    require(value["schema"] == SCHEMA and value["addon"] == ADDON
            and value["platform"] == "linux/amd64"
            and value["signer_workflow"] == build_workflow(value["release_tag"]),
            "hosting add-on identity differs")
    identity(value["source_sha"], value["release_tag"], value["build_run_id"], value["build_run_attempt"])
    require(isinstance(value["services"], dict) and set(value["services"]) == {"cloudflared"},
            "hosting add-on service closure differs")
    require(isinstance(value["services"]["cloudflared"], str)
            and re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}",
                             value["services"]["cloudflared"]) is not None,
            "hosting add-on image must be the exact approved repository digest")
    require(isinstance(value["files"], dict) and set(value["files"]) == FILES,
            "hosting add-on file closure differs")
    for checksum in [*value["files"].values(), value["archive_sha256"], value["sbom_sha256"]]:
        require(isinstance(checksum, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", checksum) is not None,
                "invalid hosting add-on digest")
    positive(value["archive_size_bytes"])
    require(value["archive_size_bytes"] <= MAX_ARCHIVE, "hosting add-on archive exceeds limit")
    return value


def validate_assets(directory: Path, *, source_sha: str, release_tag: str,
                    build_run_id: int, build_run_attempt: int) -> dict:
    """Check bytes/closure after the caller authenticates each release subject."""
    identity(source_sha, release_tag, build_run_id, build_run_attempt)
    require(directory.is_dir() and not directory.is_symlink(), "invalid hosting add-on directory")
    for name, limit in ((MANIFEST, 65536), (ARCHIVE, MAX_ARCHIVE), (SBOM, 16 * 1024 * 1024)):
        path = directory / name
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
                "missing, linked or oversized hosting add-on asset")
    value = validate_manifest(decode((directory / MANIFEST).read_bytes()))
    for key, expected in {"source_sha": source_sha, "release_tag": release_tag,
                          "build_run_id": build_run_id, "build_run_attempt": build_run_attempt}.items():
        require(value[key] == expected, "hosting add-on producer or release differs")
    archive = directory / ARCHIVE
    require(archive.stat().st_size == value["archive_size_bytes"]
            and digest(archive.read_bytes()) == value["archive_sha256"], "hosting add-on archive differs")
    require(digest((directory / SBOM).read_bytes()) == value["sbom_sha256"], "hosting add-on SBOM differs")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        require(len(entries) == len(FILES) and {entry.filename for entry in entries} == FILES,
                "hosting add-on ZIP entry closure differs")
        require(sum(entry.file_size for entry in entries) <= MAX_PAYLOAD,
                "hosting add-on expanded payload exceeds limit")
        for entry in entries:
            mode = entry.external_attr >> 16
            require(not entry.is_dir() and stat.S_ISREG(mode)
                    and not (entry.flag_bits & 1) and entry.compress_type == zipfile.ZIP_STORED,
                    "hosting add-on ZIP entry type differs")
            require(digest(bundle.read(entry)) == value["files"][entry.filename],
                    "hosting add-on runtime file differs")
        composition = yaml.safe_load(bundle.read("compose.cloudflare.yml"))
        require(isinstance(composition, dict) and set(composition) == {"services"}
                and set(composition["services"]) == {"cloudflared"}
                and composition["services"]["cloudflared"]["image"] == value["services"]["cloudflared"],
                "hosting add-on Compose image closure differs")
    return value


def package(source: Path, output: Path, *, source_sha: str, release_tag: str,
            build_run_id: int, build_run_attempt: int, image: str, sbom: Path) -> dict:
    identity(source_sha, release_tag, build_run_id, build_run_attempt)
    source = source.resolve(strict=True)
    item = policy(source)
    paths = (source / POLICY, source / item["dockerfile"], source / item["compose_source"],
             *(source / name for name in item["source_files"].values()))
    require(all(not part.is_symlink() for path in paths for part in (path, *path.parents)),
            "hosting add-on source paths must not be symlinks")
    _verify_source_files(source, source_sha, paths)
    require(re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", image) is not None,
            "unapproved hosting connector image")
    require(not sbom.is_symlink() and sbom.is_file() and 0 < sbom.stat().st_size <= 16 * 1024 * 1024,
            "invalid hosting connector SBOM")
    sbom_bytes = sbom.read_bytes()
    sbom_value = json.loads(sbom_bytes)
    require(isinstance(sbom_value, dict) and sbom_value.get("bomFormat") == "CycloneDX",
            "hosting connector SBOM format differs")
    require(output.is_absolute() and not output.exists() and not output.is_symlink()
            and not output.resolve().is_relative_to(source), "hosting add-on output must be fresh and outside source")
    composition = yaml.safe_load((source / item["compose_source"]).read_text())
    require(set(composition) == {"services"} and set(composition["services"]) == {"cloudflared"},
            "hosting add-on source service closure differs")
    composition["services"]["cloudflared"]["image"] = image
    # Compose accepts JSON as YAML. A closed JSON document also lets the native
    # installer reuse its duplicate-key-rejecting parser for exact role admission.
    files = {item["compose_entry"]: encode(composition),
             **{name: runtime_payload(source, original) for name, original in item["source_files"].items()}}
    require(set(files) == FILES and sum(map(len, files.values())) <= MAX_PAYLOAD,
            "hosting add-on source file closure differs")
    output.mkdir(mode=0o700)
    with zipfile.ZipFile(output / ARCHIVE, "x", compression=zipfile.ZIP_STORED) as bundle:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(entry, data)
    archive = (output / ARCHIVE).read_bytes()
    value = validate_manifest({"schema": SCHEMA, "addon": ADDON, "platform": "linux/amd64",
        "source_sha": source_sha, "release_tag": release_tag, "build_run_id": build_run_id,
        "build_run_attempt": build_run_attempt, "signer_workflow": build_workflow(release_tag),
        "services": {"cloudflared": image}, "files": {name: digest(data) for name, data in files.items()},
        "archive_sha256": digest(archive), "archive_size_bytes": len(archive), "sbom_sha256": digest(sbom_bytes)})
    (output / MANIFEST).write_bytes(encode(value))
    (output / SBOM).write_bytes(sbom_bytes)
    return validate_assets(output, source_sha=source_sha, release_tag=release_tag,
                           build_run_id=build_run_id, build_run_attempt=build_run_attempt)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--build-run-id", required=True, type=int)
    parser.add_argument("--build-run-attempt", required=True, type=int)
    parser.add_argument("--image", required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    args = parser.parse_args()
    package(args.source, args.output, source_sha=args.source_sha, release_tag=args.release_tag,
            build_run_id=args.build_run_id, build_run_attempt=args.build_run_attempt,
            image=args.image, sbom=args.sbom)


if __name__ == "__main__":
    main()
