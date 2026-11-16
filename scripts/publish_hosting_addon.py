#!/usr/bin/env python3
"""Sign and publish the optional connector after its exact core release."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from hosting_addon import ASSETS, MANIFEST, build_workflow, validate_assets
from installer_release import decode, require, validate_inventory
from publish_nightly_release import PROVENANCE_LIMIT, REPOSITORY, command, policy, provenance_files
from release_transaction import file_digest
from verify_installer_provenance import local_file, verify_subject


def publication_files() -> set[str]:
    return {name + suffix for name in ASSETS for suffix in ("", ".sigstore.json", ".provenance.jsonl")}


def core_assets(tag: str) -> set[str]:
    source = Path(__file__).resolve().parents[1]
    if build_workflow(tag) == ".github/workflows/nightly-release.yml":
        payloads = set(policy(source))
        return payloads | {name + ".sigstore.json" for name in payloads} | provenance_files() | {"RELEASE-SHA256SUMS"}
    # The existing stable publisher owns this policy. Do not maintain a second
    # stable asset table or infer a loose allowlist from the remote response.
    raw = command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
                  'source "$1"; printf "%s\\n" "${OPERATOR_RELEASE_ASSETS[@]}"', "--",
                  str(source / "scripts/operator-release-assets.sh"))
    names = raw.splitlines()
    require(len(names) == 32 and len(set(names)) == 32, "stable core asset policy differs")
    return set(names)


def validate(directory: Path) -> dict:
    local_file(directory / MANIFEST, maximum=65536, private=True)
    value = decode((directory / MANIFEST).read_bytes())
    require(os.environ.get("GITHUB_REF") == "refs/heads/main"
            and value["source_sha"] == os.environ.get("GITHUB_SHA")
            and str(value["build_run_id"]) == os.environ.get("GITHUB_RUN_ID")
            and str(value["build_run_attempt"]) == os.environ.get("GITHUB_RUN_ATTEMPT"),
            "hosting add-on is not from this protected-main attempt")
    return validate_assets(directory, source_sha=value["source_sha"], release_tag=value["release_tag"],
        build_run_id=value["build_run_id"], build_run_attempt=value["build_run_attempt"])


def verify_signatures(directory: Path) -> dict:
    value = validate(directory)
    for name in ASSETS:
        local_file(directory / (name + ".sigstore.json"), maximum=PROVENANCE_LIMIT, private=True)
        command("cosign", "verify-blob", str(directory / name), "--bundle",
                str(directory / (name + ".sigstore.json")), "--certificate-identity",
                f"https://github.com/{REPOSITORY}/{value['signer_workflow']}@refs/heads/main",
                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
    return value


def sign(directory: Path) -> None:
    validate(directory)
    require({p.name for p in directory.iterdir()} == set(ASSETS), "unexpected unsigned add-on asset")
    for name in ASSETS:
        command("cosign", "sign-blob", "--yes", "--bundle",
                str(directory / (name + ".sigstore.json")), str(directory / name))


def export_provenance(directory: Path, bundle: Path, gh: Path) -> None:
    value = verify_signatures(directory)
    require(bundle.is_file() and not bundle.is_symlink()
            and 0 < bundle.stat().st_size <= PROVENANCE_LIMIT, "invalid add-on provenance bundle")
    with bundle.open("rb") as source:
        raw = source.read(PROVENANCE_LIMIT + 1)
    require(0 < len(raw) <= PROVENANCE_LIMIT, "invalid add-on provenance bundle")
    with tempfile.TemporaryDirectory(prefix="marty-addon-provenance-") as temporary:
        held = Path(temporary).resolve() / "bundle.jsonl"
        held.write_bytes(raw)
        for name in ASSETS:
            verify_subject(directory / name, held, gh=gh, workflow=value["signer_workflow"],
                source_sha=value["source_sha"], run_id=value["build_run_id"],
                run_attempt=value["build_run_attempt"])
        for name in ASSETS:
            with (directory / (name + ".provenance.jsonl")).open("xb") as output:
                output.write(raw)


def publish(directory: Path, gh: Path) -> None:
    value = verify_signatures(directory)
    expected = publication_files()
    require({p.name for p in directory.iterdir()} == expected, "signed add-on asset closure differs")
    require(all(p.is_file() and not p.is_symlink() and p.stat().st_size > 0
                for p in directory.iterdir()), "linked or empty signed add-on asset")
    for name in ASSETS:
        local_file(directory / (name + ".provenance.jsonl"), maximum=PROVENANCE_LIMIT, private=True)
        verify_subject(directory / name, directory / (name + ".provenance.jsonl"), gh=gh,
            workflow=value["signer_workflow"], source_sha=value["source_sha"], run_id=value["build_run_id"],
            run_attempt=value["build_run_attempt"])
    tag = value["release_tag"]
    release = json.loads(command("gh", "api", f"repos/{REPOSITORY}/releases/tags/{tag}"))
    nightly = build_workflow(tag) == ".github/workflows/nightly-release.yml"
    require(release["tag_name"] == tag and release["prerelease"] is nightly and release["draft"] is False,
            "the expected core release has not been published")
    ref = json.loads(command("gh", "api", f"repos/{REPOSITORY}/git/ref/tags/{tag}"))
    require(ref["object"]["type"] == "tag", "core source tag is not annotated")
    annotated = json.loads(command("gh", "api", f"repos/{REPOSITORY}/git/tags/{ref['object']['sha']}"))
    require(annotated["tag"] == tag and annotated["object"]["type"] == "commit"
            and annotated["object"]["sha"] == value["source_sha"], "core and add-on source differ")
    core = core_assets(tag)
    names = [item["name"] for item in release["assets"]]
    require(len(names) == len(set(names)) and core <= set(names) <= core | expected
            and all(item["state"] == "uploaded" and item["size"] > 0 for item in release["assets"]),
            "published core or optional asset closure differs")
    # A rerun must not append an attempt-2 connector to an immutable attempt-1
    # core, even when both were built from the same commit and release tag.
    with tempfile.TemporaryDirectory(prefix="marty-addon-core-") as temporary:
        core_directory = Path(temporary).resolve()
        for name, limit in (("installer-inventory.json", 65536),
                            ("installer-inventory.json.sigstore.json", PROVENANCE_LIMIT),
                            ("installer-inventory.json.provenance.jsonl", PROVENANCE_LIMIT)):
            item = next(item for item in release["assets"] if item["name"] == name)
            require(0 < item["size"] <= limit, "published core inventory exceeds bound")
            command("gh", "release", "download", tag, "--repo", REPOSITORY,
                    "--pattern", name, "--dir", temporary)
            local_file(core_directory / name, maximum=limit, private=True)
        subject = core_directory / "installer-inventory.json"
        verify_subject(subject, core_directory / "installer-inventory.json.provenance.jsonl", gh=gh,
            workflow=value["signer_workflow"], source_sha=value["source_sha"], run_id=value["build_run_id"],
            run_attempt=value["build_run_attempt"])
        command("cosign", "verify-blob", str(subject), "--bundle",
                str(core_directory / "installer-inventory.json.sigstore.json"), "--certificate-identity",
                f"https://github.com/{REPOSITORY}/{value['signer_workflow']}@refs/heads/main",
                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
        inventory = decode(subject.read_bytes())
        validate_inventory(inventory)
        require(all(inventory[key] == value[key] for key in
                    ("source_sha", "release_tag", "build_run_id", "build_run_attempt")),
                "published core and optional producer attempt differ")
    present = {a["name"] for a in release["assets"]} & expected
    # Reconcile an interrupted upload without replacing any existing bytes.
    with tempfile.TemporaryDirectory(prefix="marty-addon-published-") as temporary:
        for name in sorted(present):
            command("gh", "release", "download", tag, "--repo", REPOSITORY,
                    "--pattern", name, "--dir", temporary)
            require(file_digest(Path(temporary) / name) == file_digest(directory / name),
                    "existing add-on asset differs; refusing overwrite")
        missing = expected - present
        if missing:
            command("gh", "release", "upload", tag, "--repo", REPOSITORY,
                    *[str(directory / name) for name in sorted(missing)])
        for name in sorted(missing):
            command("gh", "release", "download", tag, "--repo", REPOSITORY,
                    "--pattern", name, "--dir", temporary)
            require(file_digest(Path(temporary) / name) == file_digest(directory / name),
                    "published add-on bytes differ")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("sign", "export-provenance", "publish"), required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--gh", type=Path)
    parser.add_argument("--provenance-bundle", type=Path)
    args = parser.parse_args()
    directory = args.assets.resolve(strict=True)
    if args.phase == "sign":
        require(args.gh is None and args.provenance_bundle is None, "unexpected signing argument")
        sign(directory)
    else:
        require(args.gh is not None and args.gh.is_absolute(), "explicit trusted verifier path required")
        if args.phase == "export-provenance":
            require(args.provenance_bundle is not None, "provenance action output required")
            export_provenance(directory, args.provenance_bundle, args.gh)
        else:
            require(args.provenance_bundle is None, "unexpected publication bundle")
            publish(directory, args.gh)


if __name__ == "__main__":
    main()
