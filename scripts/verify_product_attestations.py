#!/usr/bin/env python3
"""Bind gh-verified producer attestations to exact product payload and images.

The caller must first run `gh attestation verify` with the exact repository,
signer workflow, source digest/ref, and hosted-runner constraints. JSON files
alone are not proof of signature verification or a successful Actions run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

WORKFLOW = "https://github.com/ElevenID/marty-ui/.github/workflows/product-packages.yml@refs/heads/main"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_json(path: Path):
    raw = path.read_bytes()
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    return json.loads(raw.decode(encoding))


def verified_statement(path: Path, source: str, run: str, attempt: str) -> dict:
    entries = read_json(path)
    require(isinstance(entries, list) and len(entries) == 1,
            "expected one verified producer attestation")
    result = entries[0]["verificationResult"]
    cert = result["signature"]["certificate"]
    invocation = f"https://github.com/ElevenID/marty-ui/actions/runs/{run}/attempts/{attempt}"
    require(cert.get("subjectAlternativeName") == WORKFLOW
            and cert.get("githubWorkflowRepository") == "ElevenID/marty-ui"
            and cert.get("githubWorkflowRef") == "refs/heads/main"
            and cert.get("sourceRepositoryDigest") == source
            and cert.get("sourceRepositoryRef") == "refs/heads/main"
            and cert.get("runnerEnvironment") == "github-hosted"
            and cert.get("runInvocationURI") == invocation,
            "attestation certificate identity differs")
    statement = result["statement"]
    require(statement.get("predicateType") == "https://slsa.dev/provenance/v1"
            and statement.get("predicate", {}).get("runDetails", {})
                .get("metadata", {}).get("invocationId") == invocation,
            "attested producer invocation differs")
    return statement


def verify(payload_path: Path, registry_path: Path, checksum_path: Path,
           attestations: Path) -> dict:
    payload = read_json(payload_path)
    registry = read_json(registry_path)
    require(payload.get("result") == registry.get("result") == "pass"
            and registry.get("product") == payload.get("product")
            and registry.get("archive_sha256") == payload.get("archive_sha256"),
            "payload and registry reports differ")
    run = payload["producer_run_id"]
    attempt = payload["producer_run_attempt"]
    source = payload["source_sha"]
    archive_subject = {
        "name": "product-package.tar.gz",
        "digest": {"sha256": payload["archive_sha256"][7:]},
    }
    checksum_subject = {
        "name": "product-package.tar.gz.sha256",
        "digest": {"sha256": hashlib.sha256(checksum_path.read_bytes()).hexdigest()},
    }
    for name in ("archive.json", "checksum.json"):
        statement = verified_statement(attestations / name, source, run, attempt)
        require(archive_subject in statement.get("subject", [])
                and checksum_subject in statement.get("subject", []),
                "archive attestation subjects differ")
    registry_roles = {image["role"]: image for image in registry["images"]}
    require(set(registry_roles) == {image["role"] for image in payload["images"]},
            "registry image roles differ from package")
    for image in payload["images"]:
        role = image["role"]
        require(registry_roles[role]["uri"] == image["uri"]
                and registry_roles[role]["index_digest"] == image["digest"],
                "registry image digest differs from package")
        statement = verified_statement(attestations / f"{role}.json", source,
                                       run, attempt)
        require({"name": image["uri"],
                 "digest": {"sha256": image["digest"][7:]}}
                in statement.get("subject", []),
                "signed image digest differs from package")
    return {
        "schema": "marty.product-producer-attestation-verification/v1",
        "product": payload["product"],
        "source_sha": source,
        "producer_run_id": run,
        "producer_run_attempt": attempt,
        "archive_sha256": payload["archive_sha256"],
        "image_roles": sorted(registry_roles),
        "result": "pass",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-report", type=Path, required=True)
    parser.add_argument("--registry-report", type=Path, required=True)
    parser.add_argument("--checksum", type=Path, required=True)
    parser.add_argument("--attestations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.payload_report, args.registry_report, args.checksum,
                    args.attestations)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
