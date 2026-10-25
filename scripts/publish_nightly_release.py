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
from installer_release import verify_inventory_assets
from verify_installer_provenance import verify_subject

REPOSITORY = "ElevenID/marty-ui"
INSTALLER_SUBJECTS = ("install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip",
                      "prepared-selfhost-images.json", "installer-inventory.json")
PROVENANCE_LIMIT = 1024 * 1024  # install.sh's anonymous transport bound


def provenance_files() -> set[str]:
    return {name + ".provenance.jsonl" for name in INSTALLER_SUBJECTS}


def verify_installer_provenance(assets: Path, candidate: dict, run_id: str, gh: Path) -> None:
    for name in INSTALLER_SUBJECTS:
        bundle = assets / (name + ".provenance.jsonl")
        require(not bundle.is_symlink() and bundle.is_file()
                and 0 < bundle.stat().st_size <= PROVENANCE_LIMIT,
                "missing or oversized installer provenance sidecar")
        verify_subject(assets / name, bundle, gh=gh,
                       workflow=WORKFLOW, source_sha=candidate["source_sha"],
                       run_id=int(run_id), run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))


def export_provenance(assets: Path, source: Path, tag: str, run_id: str, bundle: Path, gh: Path) -> None:
    """Export verified offline evidence; never attest sidecars recursively."""
    candidate = verify_signed(assets, source, tag, run_id, with_provenance=False)
    require(not bundle.is_symlink() and bundle.is_file(), "invalid provenance action output")
    with bundle.open("rb") as stream:
        raw = stream.read(PROVENANCE_LIMIT + 1)
    require(0 < len(raw) <= PROVENANCE_LIMIT, "provenance bundle exceeds installer transport bound")
    # Verify the held copy against every exact subject before exposing any output.
    with tempfile.TemporaryDirectory(prefix="nightly-installer-provenance-") as temporary:
        staged = Path(temporary).resolve() / "bundle.jsonl"
        staged.write_bytes(raw)
        for name in INSTALLER_SUBJECTS:
            verify_subject(assets / name, staged, gh=gh,
                           workflow=WORKFLOW, source_sha=candidate["source_sha"],
                           run_id=int(run_id), run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))
        for name in sorted(provenance_files()):
            with (assets / name).open("xb") as output:
                output.write(raw)


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
    require(len(files) == 19 and len(set(files)) == len(files)
            and {"install.sh", "installer-inventory.json"}.issubset(files)
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
    verify_inventory_assets(assets, source_sha=revision, release_tag=tag,
                            build_run_id=int(run_id),
                            build_run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))
    require((assets / "install.sh").read_bytes() == (source / "install.sh").read_bytes(),
            "installer bootstrap differs from exact source")
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


def verify_signed(assets: Path, source: Path, tag: str, run_id: str, *,
                  with_provenance: bool = True, gh: Path | None = None) -> dict:
    candidate, files = validate(assets, source, tag, run_id)
    inventory = set(files + [name + ".sigstore.json" for name in files])
    sidecars = provenance_files() if with_provenance else set()
    require({path.name for path in assets.iterdir()} == inventory | {"RELEASE-SHA256SUMS"} | sidecars,
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
    # Checksums cover signed payloads and signatures. Sidecars authenticate those
    # same bytes independently; sidecars are not their own attestation subjects.
    if with_provenance:
        require(gh is not None, "explicit trusted GitHub verifier path required")
        verify_installer_provenance(assets, candidate, run_id, gh)
    return candidate


def publish(assets: Path, source: Path, tag: str, run_id: str, gh: Path) -> None:
    candidate = verify_signed(assets, source, tag, run_id, gh=gh)
    for path in sorted(assets.iterdir()):
        if path.name in provenance_files():
            continue
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
    parser.add_argument("--phase", choices=["sign", "export-provenance", "publish"], required=True)
    parser.add_argument("--provenance-bundle", type=Path)
    parser.add_argument("--gh", type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if args.phase != "sign":
        require(args.gh is not None and args.gh.is_absolute(), "explicit trusted GitHub verifier path required")
    if args.phase == "export-provenance":
        require(args.provenance_bundle is not None, "provenance action output is required")
        export_provenance(args.assets.resolve(), args.source.resolve(), args.tag,
                          args.run_id, args.provenance_bundle, args.gh)
        return
    require(args.provenance_bundle is None, "provenance bundle is only valid for export")
    if args.phase == "sign":
        sign(args.assets.resolve(), args.source.resolve(), args.tag, args.run_id)
    else:
        publish(args.assets.resolve(), args.source.resolve(), args.tag, args.run_id, args.gh)


if __name__ == "__main__":
    main()
