#!/usr/bin/env python3
"""Authenticate one hosted product report and bind it to its producer archive.

The output is a pending runtime-qualification record, never a promotion decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from product_evidence_intake import bind_report, read_json, require

REPO = "ElevenID/marty-ui"
PRODUCER_WORKFLOW = ".github/workflows/product-packages.yml"
VERIFIER_WORKFLOW = ".github/workflows/product-verification.yml"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN = re.compile(r"[1-9][0-9]*\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SUBJECTS = {"verification.json", "verification-detail.json", "verification.json.sha256"}


def gh(*args: str) -> bytes:
    return subprocess.check_output(["gh", *args], stderr=subprocess.PIPE)


def api(path: str) -> dict:
    return json.loads(gh("api", f"repos/{REPO}/{path}"))


def exact_run(run_id: str, workflow: str) -> dict:
    require(RUN.fullmatch(run_id) is not None, "run ID is invalid")
    run = api(f"actions/runs/{run_id}")
    require(
        run.get("id") == int(run_id)
        and run.get("repository", {}).get("full_name") == REPO
        and run.get("path") == workflow
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] > 0
        and isinstance(run.get("head_sha"), str)
        and SHA.fullmatch(run["head_sha"]) is not None,
        "run is not a successful protected-main product workflow",
    )
    return run


def exact_artifact(run: dict, name: str) -> dict:
    artifacts = api(f"actions/runs/{run['id']}/artifacts").get("artifacts", [])
    found = [item for item in artifacts if item.get("name") == name]
    require(len(found) == 1, "exact workflow artifact is absent or ambiguous")
    artifact = found[0]
    require(
        artifact.get("expired") is False
        and artifact.get("workflow_run", {}).get("id") == run["id"]
        and artifact["workflow_run"].get("head_sha") == run["head_sha"]
        and artifact["workflow_run"].get("head_branch") == "main"
        and isinstance(artifact.get("digest"), str)
        and DIGEST.fullmatch(artifact["digest"]) is not None,
        "workflow artifact identity is invalid or expired",
    )
    return artifact


def download(run: dict, artifact: dict, destination: Path, expected: set[str]) -> None:
    destination.mkdir()
    gh(
        "run", "download", str(run["id"]), "--repo", REPO,
        "--name", artifact["name"], "--dir", str(destination),
    )
    actual = {item.name for item in destination.iterdir() if item.is_file()}
    require(actual == expected and len(list(destination.iterdir())) == len(expected),
            "downloaded artifact file set changed")
    require(all(not item.is_symlink() for item in destination.iterdir()),
            "downloaded artifact contains a link")


def signed_subject(path: Path, run: dict) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    arguments = (
        "attestation", "verify", str(path), "--repo", REPO,
        "--signer-workflow", f"{REPO}/{VERIFIER_WORKFLOW}",
        "--source-digest", run["head_sha"], "--source-ref", "refs/heads/main",
        "--deny-self-hosted-runners", "--format", "json",
    )
    for attempt in range(3):
        try:
            verified = json.loads(gh(*arguments))
            break
        except subprocess.CalledProcessError:
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
    invocation = f"https://github.com/{REPO}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
    signer = f"https://github.com/{REPO}/{VERIFIER_WORKFLOW}@refs/heads/main"
    for item in verified:
        result = item.get("verificationResult", {})
        certificate = result.get("signature", {}).get("certificate", {})
        subjects = result.get("statement", {}).get("subject", [])
        if (
            certificate.get("runInvocationURI") == invocation
            and certificate.get("subjectAlternativeName") == signer
            and certificate.get("githubWorkflowSHA") == run["head_sha"]
            and certificate.get("githubWorkflowRepository") == REPO
            and certificate.get("githubWorkflowRef") == "refs/heads/main"
            and certificate.get("runnerEnvironment") == "github-hosted"
            and any(subject.get("name") == path.name
                    and subject.get("digest", {}).get("sha256") == digest
                    for subject in subjects)
        ):
            return "sha256:" + digest
    raise ValueError("signed report subject or verifier invocation differs")


def package_from_archive(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as source:
        members = [item for item in source if item.name == "product-package.json"]
        require(len(members) == 1 and members[0].isfile()
                and 0 < members[0].size <= 1024 * 1024,
                "candidate archive has no unique bounded product manifest")
        extracted = source.extractfile(members[0])
        require(extracted is not None, "candidate manifest cannot be read")
        content = extracted.read(1024 * 1024 + 1)
        require(len(content) == members[0].size, "candidate manifest size differs")
    destination.write_bytes(content)
    return destination


def authenticate(product: str, producer_id: str, verifier_id: str) -> dict:
    require(product in {"marty-server", "marty-console"}, "product is invalid")
    verifier = exact_run(verifier_id, VERIFIER_WORKFLOW)
    producer = exact_run(producer_id, PRODUCER_WORKFLOW)
    report_name = (f"product-verification-{product}-{producer_id}-"
                   f"{verifier_id}-{verifier['run_attempt']}")
    report_artifact = exact_artifact(verifier, report_name)
    with tempfile.TemporaryDirectory(prefix="marty-product-intake-") as temporary:
        root = Path(temporary)
        reports = root / "reports"
        download(verifier, report_artifact, reports, SUBJECTS)
        signed = {name: signed_subject(reports / name, verifier)
                  for name in sorted(SUBJECTS)}
        checksum = (reports / "verification.json.sha256").read_text(encoding="ascii")
        require(checksum == signed["verification.json"].removeprefix("sha256:")
                + "  verification.json\n", "signed report checksum differs")
        report = read_json(reports / "verification.json")
        detail = read_json(reports / "verification-detail.json")
        require(
            report.get("verification") == {
                "repository": REPO, "workflow": VERIFIER_WORKFLOW,
                "run_id": verifier_id, "run_attempt": str(verifier["run_attempt"]),
                "conclusion": "success",
            }
            and report.get("candidate", {}).get("product") == product
            and report["candidate"].get("producer") == {
                "workflow": PRODUCER_WORKFLOW, "run_id": producer_id,
                "run_attempt": str(producer["run_attempt"]),
            }
            and report["candidate"].get("source") == {
                "repository": REPO, "commit": producer["head_sha"],
            },
            "signed report identity differs from authenticated runs",
        )
        candidate_name = (f"{product}-{report['candidate']['version']}-candidate-"
                          f"{producer_id}-{producer['run_attempt']}")
        candidate_artifact = exact_artifact(producer, candidate_name)
        require(
            detail.get("schema") == "marty.product-artifact-verification-detail/v1"
            and detail.get("producer_artifact_id") == str(candidate_artifact["id"])
            and detail.get("producer_artifact_digest") == candidate_artifact["digest"],
            "signed detail differs from authenticated producer artifact",
        )
        candidate = root / "candidate"
        download(producer, candidate_artifact, candidate,
                 {"product-package.tar.gz", "product-package.tar.gz.sha256"})
        archive = candidate / "product-package.tar.gz"
        package = package_from_archive(archive, root / "product-package.json")
        pending = bind_report(package, archive, reports / "verification.json",
                              signed["verification.json"])
        require(pending["verification"] == report["verification"],
                "structural intake changed verifier identity")
        return {
            "schema": "marty.product-authenticated-verification/v1",
            "state": "pending_runtime_qualification",
            "candidate": pending["candidate"],
            "verification": pending["verification"],
            "verification_report_sha256": signed["verification.json"],
            "signed_subjects": signed,
            "verifier_source_sha": verifier["head_sha"],
            "verifier_artifact": {
                "id": str(report_artifact["id"]), "digest": report_artifact["digest"],
            },
            "producer_artifact": {
                "id": str(candidate_artifact["id"]),
                "digest": candidate_artifact["digest"],
            },
            "required_runtime_evidence": (
                ["server_without_console"] if product == "marty-server"
                else ["selected_server_console_compatibility"]
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", choices=("marty-server", "marty-console"), required=True)
    parser.add_argument("--producer-run-id", required=True)
    parser.add_argument("--verifier-run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = authenticate(args.product, args.producer_run_id, args.verifier_run_id)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
