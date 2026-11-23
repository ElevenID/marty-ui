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
import web_auth as auth
import web_release_authorization as local_approval
import website_release as web
import website_producer_policy as policy

PROOF_LIMIT = 4 * 1024 * 1024
JSON_LIMIT = 1024 * 1024


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def validate_producer(producer: dict, *, role: str | None = None) -> dict:
    # Existing generic callers retain legacy-only authority. The standalone
    # producer is admitted only by an explicit website boundary.
    return policy.validate_producer(producer, role="composition" if role is None else role)


def parse_verified_json(output: str) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            ui.require(key not in result, "duplicate verifier field")
            result[key] = value
        return result
    ui.require(isinstance(output, str) and len(output) <= verifier.MAX_OUTPUT, "invalid verifier output")
    return json.loads(output, object_pairs_hook=pairs)


def verified_certificate(output: str, producer: dict, *, role: str | None = None) -> dict | None:
    validate_producer(producer, role=role)
    try:
        result = parse_verified_json(output)
        ui.require(isinstance(result, list) and len(result) == 1, "one original attestation is required")
        ui.require(isinstance(result[0]["attestation"], dict), "verified attestation missing")
        certificate = result[0]["verificationResult"]["signature"]["certificate"]
        ui.require(isinstance(certificate, dict), "original web producer certificate missing")
        authorization = None
        if certificate.get("runnerEnvironment") == "self-hosted":
            authorization = local_approval.verified_authorization(result[0], producer, role)
        repository, source_sha = producer["repository"], producer["source_sha"]
        expected = {
            "issuer": verifier.ISSUER,
            "runInvocationURI": f"https://github.com/{repository}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}",
            "runnerEnvironment": "self-hosted" if authorization is not None else "github-hosted",
            "sourceRepositoryURI": f"https://github.com/{repository}",
            "sourceRepositoryDigest": source_sha, "sourceRepositoryRef": web.REF,
            "sourceRepositoryIdentifier": policy.producer_policy(repository, role="composition" if role is None else role)["repository_id"],
            "buildSignerURI": f"https://github.com/{repository}/{producer['workflow']}@{web.REF}",
        }
        ui.require(isinstance(certificate, dict) and all(certificate.get(key) == value for key, value in expected.items()),
                   "original web producer certificate differs")
        for key, value in {"githubWorkflowRepository": repository, "githubWorkflowSHA": source_sha,
                           "githubWorkflowRef": web.REF}.items():
            ui.require(key not in certificate or certificate[key] == value, "legacy producer certificate differs")
        return authorization
    except (KeyError, TypeError, IndexError, json.JSONDecodeError):
        raise ValueError("web producer attestation is invalid") from None


def attestation_arguments(producer: dict, *, role: str | None = None) -> list[str]:
    validate_producer(producer, role=role)
    repository = producer["repository"]
    arguments = ["--repo", repository, "--signer-workflow", repository + "/" + producer["workflow"],
                 "--source-ref", web.REF, "--source-digest", producer["source_sha"],
                 "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"]
    if repository != ui.COMMERCE_REPOSITORY or role is None:
        arguments.append("--deny-self-hosted-runners")
    if repository == ui.COMMERCE_REPOSITORY:
        # Private producers retain local bundles from GitHub's private Sigstore
        # even when their plan does not provide GitHub attestation storage.
        arguments.append("--no-public-good")
    return arguments


def signature_arguments(producer: dict, *, role: str | None = None) -> list[str]:
    validate_producer(producer, role=role)
    return ["--certificate-identity", f"https://github.com/{producer['repository']}/{producer['workflow']}@{web.REF}",
            "--certificate-oidc-issuer", verifier.ISSUER]


def verify_subject(subject: Path, *, producer: dict, gh: Path, cosign: Path,
                   runner: verifier.Run = verifier.command, role: str | None = None) -> dict | None:
    validate_producer(producer, role=role)
    if role is not None:
        allowed = {
            "website": {"website-release.json"},
            "application": {"production-web-release.json", "application-web-compatibility.json", "application-release.json",
                            "production-deployment.json", "production-openbao.zip", "ui.sbom.cdx.json", "ui-build-evidence.json"},
            "composition": {"web-composition.json", "web-composition.zip"},
        }
        ui.require(subject.name in allowed[role], "subject does not belong to the selected producer role")
    provenance = subject.with_name(subject.name + ".provenance.jsonl")
    signature = subject.with_name(subject.name + ".sigstore.json")
    for path in (subject, provenance, signature):
        verifier.local_file(path, private=True, maximum=None if path == subject else PROOF_LIMIT)
    for path in (gh, cosign):
        verifier.local_file(path)
    before = {path: file_digest(path) for path in (subject, provenance, signature)}
    output = runner([str(gh), "attestation", "verify", str(subject), "--bundle", str(provenance),
                     *attestation_arguments(producer, role=role)])
    authorization = verified_certificate(output, producer, role=role)
    runner([str(cosign), "verify-blob", str(subject), "--bundle", str(signature), *signature_arguments(producer, role=role)])
    ui.require(all(file_digest(path) == digest for path, digest in before.items()),
               "web evidence changed during verification")
    return authorization


def verify_image(image: dict, provenance: Path, *, producer: dict, gh: Path, cosign: Path,
                 runner: verifier.Run = verifier.command, registry_config: Path | None = None,
                 role: str | None = None) -> dict | None:
    validate_producer(producer, role=role)
    web.object_keys(image, {"uri", "digest", "platform"}, "web image")
    # Omitted roles keep the historical image API, after legacy-only producer
    # validation above. New website ownership must always be explicit.
    image_role = role or ("website" if image["uri"] in {web.PUBLIC_IMAGE, web.COMMERCE_IMAGE} else "application")
    image_owner = policy.image_policy(image["uri"], role=image_role)
    ui.require(image["platform"] == "linux/amd64", "unknown web image")
    web.image_digest(image["digest"])
    private_image = image["uri"] in {web.COMMERCE_IMAGE, ui.COMMERCE_IMAGE}
    ui.require(producer["repository"] == image_owner["repository"],
               "image and original producer differ")
    verifier.local_file(provenance, maximum=PROOF_LIMIT, private=True)
    for path in (gh, cosign):
        verifier.local_file(path)
    if private_image:
        ui.require(registry_config is not None, "private web OCI verification requires --registry-config")
        image_runner = lambda args: auth.registry_command(args, config=registry_config)
    else:
        image_runner = runner
    before = ui.digest(provenance.read_bytes())
    reference = image["uri"] + "@" + image["digest"]
    output = image_runner([str(gh), "attestation", "verify", "oci://" + reference, "--bundle", str(provenance),
                           *attestation_arguments(producer, role=role)])
    authorization = verified_certificate(output, producer, role=role)
    verified = parse_verified_json(image_runner([str(cosign), "verify", reference, *signature_arguments(producer, role=role)]))
    try:
        ui.require(isinstance(verified, list) and len(verified) > 0
                   and all(item["critical"]["image"]["docker-manifest-digest"] == image["digest"] for item in verified),
                   "verified image digest differs")
    except (TypeError, KeyError):
        raise ValueError("image signature result is invalid") from None
    ui.require(ui.digest(provenance.read_bytes()) == before, "image provenance changed during verification")
    return authorization


def read_metadata(path: Path) -> dict:
    verifier.local_file(path, maximum=JSON_LIMIT, private=True)
    return web.read(path)


def verify_website(directory: Path, *, gh: Path, cosign: Path, source_sha: str | None = None,
                   commerce_source_sha: str | None = None, runner: verifier.Run = verifier.command,
                   registry_config: Path | None = None, assignment_reader: auth.GitHubReader | None = None) -> dict:
    path = directory / "website-release.json"
    release = web.validate_release(read_metadata(path), source_sha=source_sha, commerce_source_sha=commerce_source_sha)
    routes = read_metadata(directory / "web-surface-routes.json")
    ui.require(web.route_identity(routes) == release["image_metadata"]["route_contract"], "website route contract differs")
    authorization = verify_subject(path, producer=release["producer"], gh=gh, cosign=cosign, runner=runner, role="website")
    image_authorization = verify_image(release["image"], directory / "image.provenance.jsonl", producer=release["producer"],
                 gh=gh, cosign=cosign, runner=runner, registry_config=registry_config, role="website")
    ui.require(authorization == image_authorization, "website and image signing approvals differ")
    if authorization is not None:
        ui.require(authorization["inputs"]["website_source_sha"] == release["source_sha"],
                   "approved independent website source differs")
        if assignment_reader is not None:
            local_approval.check_assignment(authorization, parse_verified_json(assignment_reader.jobs()), completed=True)
    ui.require(read_metadata(path) == release, "website metadata changed after verification")
    return release


def verify_application(directory: Path, *, gh: Path, cosign: Path,
                       runner: verifier.Run = verifier.command,
                       registry_config: Path | None = None,
                       assignment_reader: auth.GitHubReader | None = None) -> tuple[dict, dict]:
    path = directory / "production-web-release.json"
    release = web.validate_combined_release(read_metadata(path))
    compatibility_path = directory / "application-web-compatibility.json"
    compatibility = read_metadata(compatibility_path)
    expected = web.compatibility_record(release, compatibility.get("marker"), path.read_bytes())
    ui.require(compatibility == expected, "application compatibility differs from original release")
    producer = compatibility["producer"]
    approvals = []
    for subject in (path, compatibility_path):
        approvals.append(verify_subject(subject, producer=producer, gh=gh, cosign=cosign, runner=runner, role="application"))
    approvals.append(verify_image(release["image"], directory / "image.provenance.jsonl", producer=producer,
                 gh=gh, cosign=cosign, runner=runner, registry_config=registry_config, role="application"))
    ui.require(all(a == approvals[0] for a in approvals), "application signing approvals differ")
    if approvals[0] is not None:
        ui.require(approvals[0]["inputs"]["ui_source_sha"] == release["source_sha"]
                   and approvals[0]["inputs"]["stack_release_tag"] == "v" + release["version"],
                   "approved application source or backend release differs")
        if assignment_reader is not None:
            local_approval.check_assignment(approvals[0], parse_verified_json(assignment_reader.jobs()), completed=True)
    ui.require(read_metadata(path) == release and read_metadata(compatibility_path) == compatibility,
               "application metadata changed after verification")
    return release, compatibility


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("website", "application"))
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--gh", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--registry-config", type=Path, help="explicit private Docker config.json for private OCI reads")
    parser.add_argument("--source-sha")
    parser.add_argument("--commerce-source-sha")
    args = parser.parse_args()
    kwargs = dict(gh=args.gh.absolute(), cosign=args.cosign.absolute(), registry_config=args.registry_config)
    if args.command == "website":
        ui.require(args.source_sha is not None, "expected public website source is required")
        verify_website(args.assets.absolute(), source_sha=args.source_sha,
                       commerce_source_sha=args.commerce_source_sha, **kwargs)
    else:
        ui.require(args.source_sha is None and args.commerce_source_sha is None, "application uses authenticated original identity")
        verify_application(args.assets.absolute(), **kwargs)


if __name__ == "__main__":
    main()
