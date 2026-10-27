#!/usr/bin/env python3
"""Bind an external verifier report to an independent product candidate.

This is structural intake, not verification of the report's origin or its
verdicts. The promotion workflow must authenticate the report artifact and
workflow run before consuming the returned pending record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
from pathlib import Path

COMPOSE = runpy.run_path(str(Path(__file__).with_name("compose_product_packages.py")))
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]*\Z")
CHECKS = {"payload", "provenance", "sbom", "cross_host"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant: {value}")


def read_json(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "evidence input must be a regular file")
    require(path.stat().st_size <= 1024 * 1024, "evidence JSON is too large")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    require(isinstance(value, dict), "evidence input must be an object")
    return value


def candidate_identity(package: dict, package_digest: str, archive_digest: str) -> dict:
    require(
        set(package) == {
            "schema", "product", "version", "tag", "source", "api", "platforms",
            "images", "build_plan_sha256", "producer", "support_state", "qualification",
        }
        and package.get("platforms") == ["linux/amd64"]
        and isinstance(package.get("build_plan_sha256"), str)
        and SHA256.fullmatch(package["build_plan_sha256"]) is not None,
        "candidate package fields changed",
    )
    COMPOSE["package_images"](package)
    require(
        package.get("qualification") == "unqualified"
        and package.get("support_state") == "experimental",
        "candidate already claims qualification or support",
    )
    producer = package.get("producer")
    require(
        isinstance(producer, dict)
        and set(producer) == {"workflow", "run_id", "run_attempt"}
        and producer["workflow"] == ".github/workflows/product-packages.yml"
        and all(isinstance(producer[key], str) and RUN_ID.fullmatch(producer[key]) for key in ("run_id", "run_attempt")),
        "producer identity is invalid",
    )
    images = package["images"]
    require(all(isinstance(image, dict) and set(image) == {"role", "uri", "digest", "platform"} for image in images), "image fields changed")
    return {
        "archive_sha256": archive_digest,
        "package_sha256": package_digest,
        "product": package["product"],
        "version": package["version"],
        "tag": package["tag"],
        "source": package["source"],
        "producer": producer,
        "images": sorted(images, key=lambda image: image["role"]),
    }


def bind_report(
    package_path: Path,
    archive_path: Path,
    report_path: Path,
    expected_report_sha256: str,
) -> dict:
    """Return a pending record only for a passing, exact-identity report."""
    require(SHA256.fullmatch(expected_report_sha256) is not None, "trusted report digest is invalid")
    require(archive_path.is_file() and not archive_path.is_symlink(), "candidate archive must be a regular file")
    package = read_json(package_path)
    report = read_json(report_path)
    report_digest = file_digest(report_path)
    require(report_digest == expected_report_sha256, "report checksum differs from trusted input")
    candidate = candidate_identity(package, file_digest(package_path), file_digest(archive_path))
    require(set(report) == {"schema", "candidate", "verification", "checks", "result"}, "verification report fields changed")
    require(report["schema"] == "marty.product-artifact-verification/v1", "verification report schema changed")
    require(report["candidate"] == candidate, "verification report does not cover the exact candidate")
    verification = report["verification"]
    require(isinstance(verification, dict) and set(verification) == {"repository", "workflow", "run_id", "run_attempt", "conclusion"}, "verification run fields changed")
    require(verification["repository"] == "ElevenID/marty-ui", "verification repository changed")
    require(isinstance(verification["workflow"], str) and re.fullmatch(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml", verification["workflow"]) is not None, "verification workflow identity is invalid")
    require(all(isinstance(verification[key], str) and RUN_ID.fullmatch(verification[key]) for key in ("run_id", "run_attempt")), "verification run identity is invalid")
    require(verification["conclusion"] == "success", "verification workflow did not pass")
    checks = report["checks"]
    require(isinstance(checks, dict) and set(checks) == CHECKS and all(value == "pass" for value in checks.values()), "required independent verification checks did not all pass")
    require(report["result"] == "pass", "independent verification did not pass")
    return {
        "schema": "marty.product-evidence-intake/v1",
        "state": "pending_authenticated_promotion",
        "candidate": candidate,
        "verification": verification,
        "verification_report_sha256": report_digest,
        "required_checks": sorted(CHECKS),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--verification-report", type=Path, required=True)
    parser.add_argument("--trusted-report-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = bind_report(args.package, args.archive, args.verification_report, args.trusted_report_sha256)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
