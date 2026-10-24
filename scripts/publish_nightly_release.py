#!/usr/bin/env python3
"""Sign and publish only an exact installation-test nightly candidate."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from check_prepared_selfhost_consumer import verify_descriptor, verify_receipt
from nightly_release import WORKFLOW, file_digest, product_manifest, read, require, validate_preparation
from run_nightly_runtime_smoke import CASES, SCHEMA as RUNTIME_SCHEMA
from stage_selfhost_disposable_preview import verify_checksums

REPOSITORY = "ElevenID/marty-ui"


def command(*args: str, data: dict | None = None) -> str:
    result = subprocess.run(args, input=json.dumps(data) if data is not None else None,
                            capture_output=True, text=True, check=False, timeout=180)
    require(result.returncode == 0, "nightly publication command failed: " + args[0])
    return result.stdout.strip()


def policy(source: Path) -> list[str]:
    value = read(source / "release/nightly-assets.json")
    require(value["schema"] == "elevenid.nightly-installation-assets/v1"
            and value["platform"] == "linux/amd64" and value["signer_workflow"] == WORKFLOW,
            "nightly asset policy changed")
    files = value["signed_inputs"]
    require(len(files) == 17 and len(set(files)) == len(files)
            and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]+", name) for name in files),
            "invalid nightly release inventory")
    return files


def validate(assets: Path, source: Path, tag: str, run_id: str) -> tuple[dict, list[str]]:
    files = policy(source)
    require(not assets.is_symlink() and assets.is_dir(), "invalid nightly asset directory")
    for name in files:
        path = assets / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size > 0,
                "missing or linked nightly asset: " + name)
    transaction = assets / "selfhost-preparation-transaction.json"
    candidate = read(transaction)
    require(candidate.get("tag") == tag and candidate.get("build_run_id") == run_id,
            "nightly publication identity differs")
    revision = command("git", "-C", str(source), "rev-parse", "HEAD^{commit}")
    validate_preparation(candidate, source_sha=revision, stack_lock=source / "release/stack-lock.json",
                         claim_run_id=candidate["claim_run_id"])
    require(os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_SHA") == revision
            and os.environ.get("GITHUB_RUN_ID") == run_id,
            "nightly publication is not the exact main workflow run")
    verify_checksums(assets)
    verify_receipt(assets / "prepared-selfhost-bundle.zip", assets / "prepared-selfhost-images.json",
        transaction, assets / "prepared-selfhost-bundle.json", revision, run_id)
    verify_descriptor(assets / "prepared-selfhost-bundle.zip", assets / "prepared-selfhost-images.json",
        transaction, assets / "prepared-selfhost-bundle.json",
        assets / "prepared-selfhost-product-descriptor.json")
    manifest = read(assets / "stack-manifest.json")
    require(manifest == product_manifest(candidate, source / "release/stack-lock.json", manifest["generated_at"]),
            "nightly manifest differs from exact candidate")
    runtime = read(assets / "nightly-runtime.json")
    require(runtime.get("schema") == RUNTIME_SCHEMA and runtime.get("tier") == "nightly"
            and runtime.get("status") == "passed" and runtime.get("owned_cleanup") == "observed"
            and runtime.get("source_sha") == revision and runtime.get("tag") == tag
            and runtime.get("run_id") == run_id and runtime.get("cases") == list(CASES)
            and runtime.get("candidate_sha256") == file_digest(transaction)
            and runtime.get("manifest_sha256") == file_digest(assets / "stack-manifest.json")
            and runtime.get("archive_sha256") == file_digest(assets / "prepared-selfhost-bundle.zip"),
            "nightly runtime evidence is missing, incomplete or stale")
    binary = assets / "marty-deploy-linux-amd64"
    binary.chmod(0o755)
    require(command(str(binary), "--build-identity") == f"{revision}:{tag}",
            "nightly operator identity differs")
    return candidate, files


def sign(assets: Path, source: Path, tag: str, run_id: str) -> None:
    _, files = validate(assets, source, tag, run_id)
    require(set(path.name for path in assets.iterdir()) == set(files),
            "nightly candidate has unexpected assets")
    for name in files:
        command("cosign", "sign-blob", "--yes", "--bundle", str(assets / (name + ".sigstore.json")),
                str(assets / name))
    inventory = sorted(files + [name + ".sigstore.json" for name in files])
    with (assets / "RELEASE-SHA256SUMS").open("x", encoding="ascii") as stream:
        for name in inventory:
            stream.write(file_digest(assets / name).removeprefix("sha256:") + "  " + name + "\n")


def verify_signed(assets: Path, source: Path, tag: str, run_id: str) -> dict:
    candidate, files = validate(assets, source, tag, run_id)
    inventory = set(files + [name + ".sigstore.json" for name in files])
    require({path.name for path in assets.iterdir()} == inventory | {"RELEASE-SHA256SUMS"},
            "signed nightly inventory differs")
    require(all(not path.is_symlink() and path.is_file() and path.stat().st_size > 0
                for path in assets.iterdir()), "linked or empty signed nightly asset")
    actual = {}
    for line in (assets / "RELEASE-SHA256SUMS").read_text(encoding="ascii").splitlines():
        digest, separator, name = line.partition("  ")
        require(separator == "  " and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and name in inventory and name not in actual, "invalid nightly release checksums")
        actual[name] = digest
    require(set(actual) == inventory and all(file_digest(assets / name) == "sha256:" + digest
        for name, digest in actual.items()), "nightly release checksum mismatch")
    for name in files:
        command("cosign", "verify-blob", str(assets / name), "--bundle",
            str(assets / (name + ".sigstore.json")), "--certificate-identity",
            f"https://github.com/{REPOSITORY}/{WORKFLOW}@refs/heads/main",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
    return candidate


def publish(assets: Path, source: Path, tag: str, run_id: str) -> None:
    candidate = verify_signed(assets, source, tag, run_id)
    for path in sorted(assets.iterdir()):
        command("gh", "attestation", "verify", str(path), "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
                "--source-digest", candidate["source_sha"], "--deny-self-hosted-runners")
    message = (f"Installation-test nightly\nSource-SHA: {candidate['source_sha']}\n"
               f"Claim: {candidate['claim_run_id']}\nRun: {run_id}\n")
    command("git", "-C", str(source), "fetch", "--no-tags", "origin",
            "+refs/heads/main:refs/remotes/origin/main")
    require(command("git", "-C", str(source), "merge-base", candidate["source_sha"], "origin/main")
            == candidate["source_sha"], "nightly source is no longer protected main history")
    refs = command("git", "-C", str(source), "ls-remote", "--tags", "origin",
                   f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    if not refs:
        document = json.loads(command("gh", "api", "--method", "POST",
            f"repos/{REPOSITORY}/git/tags", "--input", "-", data={
                "tag": tag, "message": message,
                "object": candidate["source_sha"], "type": "commit"}))
        command("gh", "api", "--method", "POST", f"repos/{REPOSITORY}/git/refs", "--input", "-",
                data={"ref": "refs/tags/" + tag, "sha": document["sha"]})
    ref = json.loads(command("gh", "api", f"repos/{REPOSITORY}/git/ref/tags/{tag}"))
    require(ref["object"]["type"] == "tag", "nightly source ref is not annotated")
    annotated = json.loads(command("gh", "api", f"repos/{REPOSITORY}/git/tags/{ref['object']['sha']}"))
    require(annotated["object"]["type"] == "commit"
            and annotated["object"]["sha"] == candidate["source_sha"]
            and annotated["tag"] == tag and annotated["message"] == message,
            "nightly annotated source tag differs")
    lookup = subprocess.run(["gh", "api", "--include", f"repos/{REPOSITORY}/releases/tags/{tag}"],
                            capture_output=True, text=True, timeout=60)
    if lookup.returncode:
        require(re.match(r"HTTP/[0-9.]+ 404\b", lookup.stdout) is not None,
                "nightly release absence was not established")
        command("gh", "release", "create", tag, "--repo", REPOSITORY,
            "--verify-tag", "--prerelease", "--latest=false", "--title", tag + " installation testing",
            "--notes-file", str(assets / "SELFHOST-PREVIEW-README.md"),
            *[str(path) for path in sorted(assets.iterdir())])
    published = json.loads(command("gh", "api", f"repos/{REPOSITORY}/releases/tags/{tag}"))
    require(published["prerelease"] is True and published["draft"] is False
            and published["tag_name"] == tag, "nightly release tier differs")
    require(len(published["assets"]) == len(list(assets.iterdir()))
            and {item["name"] for item in published["assets"]} == {p.name for p in assets.iterdir()}
            and all(item["state"] == "uploaded" and item["size"] > 0 for item in published["assets"]),
            "published nightly asset inventory differs")
    with tempfile.TemporaryDirectory(prefix="nightly-published-") as directory:
        command("gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", directory)
        require(all(file_digest(Path(directory) / path.name) == file_digest(path)
                    for path in assets.iterdir()), "published nightly asset bytes differ")
    print(published["html_url"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["sign", "publish"], required=True)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    operation = sign if args.phase == "sign" else publish
    operation(args.assets.resolve(), args.source.resolve(), args.tag, args.run_id)


if __name__ == "__main__":
    main()
