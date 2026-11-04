#!/usr/bin/env python3
"""Authenticate original website/application producers before composition or use.

Only fixed local evidence filenames are consumed. Callers use pinned verifier
binaries and private staging; artifact-selected code is never executed. Public
and private producers retain their distinct source and certificate identities.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import ui_release as ui
import verify_installer_provenance as verifier
import website_release as web

PROOF_LIMIT = 4 * 1024 * 1024
JSON_LIMIT = 1024 * 1024


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def validate_producer(producer: dict) -> dict:
    web.object_keys(producer, {"repository", "workflow", "source_sha", "ref", "run_id", "run_attempt"}, "web producer")
    repository = producer["repository"]
    ui.require(repository in web.REPOSITORIES, "unknown web producer repository")
    workflow = ui.WORKFLOW if repository == ui.REPOSITORY else ui.COMMERCE_WORKFLOW
    ui.require(producer["workflow"] == workflow and producer["ref"] == web.REF, "web producer workflow or ref differs")
    web.full_sha(producer["source_sha"])
    for key in ("run_id", "run_attempt"):
        ui.require(isinstance(producer[key], str) and ui.RUN.fullmatch(producer[key]) is not None, "invalid web producer invocation")
    return producer


def parse_verified_json(output: str) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            ui.require(key not in result, "duplicate verifier field")
            result[key] = value
        return result
    ui.require(isinstance(output, str) and len(output) <= verifier.MAX_OUTPUT, "invalid verifier output")
    return json.loads(output, object_pairs_hook=pairs)


def verified_certificate(output: str, producer: dict) -> None:
    validate_producer(producer)
    try:
        result = parse_verified_json(output)
        ui.require(isinstance(result, list) and len(result) == 1, "one original attestation is required")
        ui.require(isinstance(result[0]["attestation"], dict), "verified attestation missing")
        certificate = result[0]["verificationResult"]["signature"]["certificate"]
        repository, source_sha = producer["repository"], producer["source_sha"]
        expected = {
            "issuer": verifier.ISSUER,
            "runInvocationURI": f"https://github.com/{repository}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}",
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": f"https://github.com/{repository}",
            "sourceRepositoryDigest": source_sha, "sourceRepositoryRef": web.REF,
            "sourceRepositoryIdentifier": web.REPOSITORIES[repository],
            "buildSignerURI": f"https://github.com/{repository}/{producer['workflow']}@{web.REF}",
        }
        ui.require(isinstance(certificate, dict) and all(certificate.get(key) == value for key, value in expected.items()),
                   "original web producer certificate differs")
        for key, value in {"githubWorkflowRepository": repository, "githubWorkflowSHA": source_sha,
                           "githubWorkflowRef": web.REF}.items():
            ui.require(key not in certificate or certificate[key] == value, "legacy producer certificate differs")
    except (KeyError, TypeError, IndexError, json.JSONDecodeError):
        raise ValueError("web producer attestation is invalid") from None


def attestation_arguments(producer: dict) -> list[str]:
    validate_producer(producer)
    repository = producer["repository"]
    return ["--repo", repository, "--signer-workflow", repository + "/" + producer["workflow"],
            "--source-ref", web.REF, "--source-digest", producer["source_sha"], "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"]


def signature_arguments(producer: dict) -> list[str]:
    validate_producer(producer)
    return ["--certificate-identity", f"https://github.com/{producer['repository']}/{producer['workflow']}@{web.REF}",
            "--certificate-oidc-issuer", verifier.ISSUER]


def verify_subject(subject: Path, *, producer: dict, gh: Path, cosign: Path,
                   runner: verifier.Run = verifier.command) -> None:
    provenance = subject.with_name(subject.name + ".provenance.jsonl")
    signature = subject.with_name(subject.name + ".sigstore.json")
    for path in (subject, provenance, signature):
        verifier.local_file(path, private=True, maximum=None if path == subject else PROOF_LIMIT)
    for path in (gh, cosign):
        verifier.local_file(path)
    before = {path: file_digest(path) for path in (subject, provenance, signature)}
    output = runner([str(gh), "attestation", "verify", str(subject), "--bundle", str(provenance),
                     *attestation_arguments(producer)])
    verified_certificate(output, producer)
    runner([str(cosign), "verify-blob", str(subject), "--bundle", str(signature), *signature_arguments(producer)])
    ui.require(all(file_digest(path) == digest for path, digest in before.items()),
               "web evidence changed during verification")


def verify_image(image: dict, provenance: Path, *, producer: dict, gh: Path, cosign: Path,
                 runner: verifier.Run = verifier.command) -> None:
    web.object_keys(image, {"uri", "digest", "platform"}, "web image")
    allowed = {web.PUBLIC_IMAGE, web.COMMERCE_IMAGE, ui.PUBLIC_IMAGE, ui.COMMERCE_IMAGE}
    ui.require(image["uri"] in allowed and image["platform"] == "linux/amd64", "unknown web image")
    web.image_digest(image["digest"])
    private_image = image["uri"] in {web.COMMERCE_IMAGE, ui.COMMERCE_IMAGE}
    ui.require(producer["repository"] == (ui.COMMERCE_REPOSITORY if private_image else ui.REPOSITORY),
               "image and original producer differ")
    verifier.local_file(provenance, maximum=PROOF_LIMIT, private=True)
    for path in (gh, cosign):
        verifier.local_file(path)
    before = ui.digest(provenance.read_bytes())
    reference = image["uri"] + "@" + image["digest"]
    output = runner([str(gh), "attestation", "verify", "oci://" + reference, "--bundle", str(provenance),
                     *attestation_arguments(producer)])
    verified_certificate(output, producer)
    verified = parse_verified_json(runner([str(cosign), "verify", reference, *signature_arguments(producer)]))
    try:
        ui.require(isinstance(verified, list) and len(verified) > 0
                   and all(item["critical"]["image"]["docker-manifest-digest"] == image["digest"] for item in verified),
                   "verified image digest differs")
    except (TypeError, KeyError):
        raise ValueError("image signature result is invalid") from None
    ui.require(ui.digest(provenance.read_bytes()) == before, "image provenance changed during verification")


def read_metadata(path: Path) -> dict:
    verifier.local_file(path, maximum=JSON_LIMIT, private=True)
    return web.read(path)


def verify_website(directory: Path, *, gh: Path, cosign: Path, source_sha: str | None = None,
                   commerce_source_sha: str | None = None, runner: verifier.Run = verifier.command) -> dict:
    path = directory / "website-release.json"
    release = web.validate_release(read_metadata(path), source_sha=source_sha, commerce_source_sha=commerce_source_sha)
    routes = read_metadata(directory / "web-surface-routes.json")
    ui.require(web.route_identity(routes) == release["image_metadata"]["route_contract"], "website route contract differs")
    verify_subject(path, producer=release["producer"], gh=gh, cosign=cosign, runner=runner)
    verify_image(release["image"], directory / "image.provenance.jsonl", producer=release["producer"],
                 gh=gh, cosign=cosign, runner=runner)
    ui.require(read_metadata(path) == release, "website metadata changed after verification")
    return release


def verify_application(directory: Path, *, gh: Path, cosign: Path,
                       runner: verifier.Run = verifier.command) -> tuple[dict, dict]:
    path = directory / "production-web-release.json"
    release = web.validate_combined_release(read_metadata(path))
    compatibility_path = directory / "application-web-compatibility.json"
    compatibility = read_metadata(compatibility_path)
    expected = web.compatibility_record(release, compatibility.get("marker"), path.read_bytes())
    ui.require(compatibility == expected, "application compatibility differs from original release")
    producer = compatibility["producer"]
    for subject in (path, compatibility_path):
        verify_subject(subject, producer=producer, gh=gh, cosign=cosign, runner=runner)
    verify_image(release["image"], directory / "image.provenance.jsonl", producer=producer,
                 gh=gh, cosign=cosign, runner=runner)
    ui.require(read_metadata(path) == release and read_metadata(compatibility_path) == compatibility,
               "application metadata changed after verification")
    return release, compatibility


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("website", "application"))
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--gh", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--source-sha")
    parser.add_argument("--commerce-source-sha")
    args = parser.parse_args()
    kwargs = dict(gh=args.gh.absolute(), cosign=args.cosign.absolute())
    if args.command == "website":
        ui.require(args.source_sha is not None, "expected public website source is required")
        verify_website(args.assets.absolute(), source_sha=args.source_sha,
                       commerce_source_sha=args.commerce_source_sha, **kwargs)
    else:
        ui.require(args.source_sha is None and args.commerce_source_sha is None, "application uses authenticated original identity")
        verify_application(args.assets.absolute(), **kwargs)


if __name__ == "__main__":
    main()
