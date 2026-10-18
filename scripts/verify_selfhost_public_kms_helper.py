"""Admit an exact, signed experimental public-KMS helper companion.

The seven-day Actions artifact is only a producer bridge. Public preview
distribution must keep the two subjects and their exact SLSA bundles together.
This is not a qualified operator release asset or a portable Linux promise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable

try:
    from .record_selfhost_public_kms_helper import MAX_SIZE, SCHEMA, record
except ImportError:
    from record_selfhost_public_kms_helper import MAX_SIZE, SCHEMA, record

REPOSITORY = "ElevenID/marty-ui"
WORKFLOW = ".github/workflows/cd.yml"
SIGNER = f"{REPOSITORY}/{WORKFLOW}"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]*\Z")
EXPECTED_FIELDS = frozenset(
    {
        "schema",
        "source_sha",
        "run_id",
        "platform",
        "binary",
        "sha256",
        "size",
        "qualification",
    }
)
Run = Callable[[list[str]], str]
Read = Callable[[str], str]
BINARY_BUNDLE = "public-kms-jwk.slsa-bundle.json"
RECEIPT_BUNDLE = "selfhost-public-kms-jwk.slsa-bundle.json"
FILES = frozenset(
    {"public-kms-jwk", "selfhost-public-kms-jwk.json", BINARY_BUNDLE, RECEIPT_BUNDLE}
)


def command(args: list[str]) -> str:
    # Public preview admission must work without the tester's GitHub account.
    with tempfile.TemporaryDirectory(prefix="marty-anonymous-gh-") as home:
        environment = os.environ.copy()
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GH_HOST"):
            environment.pop(name, None)
        environment["GH_CONFIG_DIR"] = home
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            env=environment,
        )
    if result.returncode != 0:
        raise ValueError("public-key helper provenance verification failed")
    return result.stdout


def public_run_record(url: str) -> str:
    if not url.startswith(f"https://api.github.com/repos/{REPOSITORY}/actions/"):
        raise ValueError("public-key helper producer URL is invalid")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "marty-helper-admission",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise ValueError("public-key helper producer lookup failed")
            data = response.read(1024 * 1024 + 1)
    except (OSError, ValueError) as error:
        raise ValueError("public-key helper producer lookup failed") from error
    if len(data) > 1024 * 1024:
        raise ValueError("public-key helper producer record is oversized")
    return data.decode("utf-8")


def parsed(output: str, label: str) -> object:
    try:
        return json.loads(output)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"public-key helper {label} is invalid") from exc


def verified_certificate(output: str, run_id: str, source_sha: str) -> None:
    result = parsed(output, "attestation result")
    if (
        not isinstance(result, list)
        or len(result) != 1
        or not isinstance(result[0], dict)
    ):
        raise ValueError("public-key helper needs exactly one verified attestation")
    item = result[0]
    if not isinstance(item.get("attestation"), dict):
        raise ValueError("public-key helper attestation is absent")
    verification = item.get("verificationResult")
    if not isinstance(verification, dict):
        raise ValueError("public-key helper verification result is absent")
    signature = verification.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    invocation = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/1"
    if not isinstance(certificate, dict) or (
        certificate.get("runInvocationURI") != invocation
        or certificate.get("runnerEnvironment") != "github-hosted"
        or certificate.get("githubWorkflowRepository") != REPOSITORY
        or certificate.get("githubWorkflowRef") != "refs/heads/main"
        or certificate.get("githubWorkflowSHA") != source_sha
    ):
        raise ValueError("public-key helper attestation came from another run")


def verified_run(run_id: str, source_sha: str, read: Read) -> None:
    run = parsed(
        read(f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"),
        "producer run",
    )
    if not isinstance(run, dict) or (
        type(run.get("id")) is not int
        or str(run["id"]) != run_id
        or not isinstance(run.get("repository"), dict)
        or run["repository"].get("full_name") != REPOSITORY
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != source_sha
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] != 1
        or type(run.get("workflow_id")) is not int
    ):
        raise ValueError("public-key helper producer run is not qualified")
    workflow = parsed(
        read(
            f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{run['workflow_id']}"
        ),
        "producer workflow",
    )
    if not isinstance(workflow, dict) or (
        workflow.get("path") != WORKFLOW or workflow.get("state") != "active"
    ):
        raise ValueError("public-key helper producer workflow is invalid")


def verify_subject_attestations(
    binary: Path, receipt_path: Path, source_sha: str, run_id: str, runner: Run
) -> None:
    for subject, bundle in (
        (binary, binary.parent / BINARY_BUNDLE),
        (receipt_path, receipt_path.parent / RECEIPT_BUNDLE),
    ):
        output = runner(
            [
                "gh",
                "attestation",
                "verify",
                str(subject),
                "--bundle",
                str(bundle),
                "--repo",
                REPOSITORY,
                "--signer-workflow",
                SIGNER,
                "--source-ref",
                "refs/heads/main",
                "--source-digest",
                source_sha,
                "--deny-self-hosted-runners",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--format",
                "json",
            ]
        )
        verified_certificate(output, run_id, source_sha)


def verify_owned_helper(
    directory: Path,
    source_sha: str,
    run_id: str,
    runner: Run = command,
    read: Read = public_run_record,
) -> Path:
    """Verify a caller-owned private extraction, never an ambient binary path."""
    if os.name != "posix" or os.uname().machine != "x86_64":
        raise ValueError("public-key helper reuse requires the pinned Linux host")
    if SHA.fullmatch(source_sha) is None or RUN_ID.fullmatch(run_id) is None:
        raise ValueError("public-key helper expected identity is invalid")
    if (
        directory.is_symlink()
        or not directory.is_dir()
        or directory.stat().st_uid != os.getuid()
        or stat.S_IMODE(directory.stat().st_mode) != 0o700
        or {path.name for path in directory.iterdir()} != FILES
    ):
        raise ValueError("public-key helper extraction is not private and exact")
    binary = directory / "public-kms-jwk"
    receipt_path = directory / "selfhost-public-kms-jwk.json"
    bundles = [directory / BINARY_BUNDLE, directory / RECEIPT_BUNDLE]
    if (
        receipt_path.is_symlink()
        or not receipt_path.is_file()
        or not 0 < receipt_path.stat().st_size <= 4096
        or binary.is_symlink()
        or not binary.is_file()
        or not 64 <= binary.stat().st_size <= MAX_SIZE
        or any(
            bundle.is_symlink()
            or not bundle.is_file()
            or not 0 < bundle.stat().st_size <= 2 * 1024 * 1024
            for bundle in bundles
        )
    ):
        raise ValueError("public-key helper artifact is invalid")
    receipt = parsed(receipt_path.read_text(encoding="utf-8"), "receipt")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != EXPECTED_FIELDS
        or receipt != record(binary, source_sha, run_id)
        or receipt.get("schema") != SCHEMA
    ):
        raise ValueError("public-key helper receipt differs from exact bytes")
    verified_run(run_id, source_sha, read)
    verify_subject_attestations(binary, receipt_path, source_sha, run_id, runner)
    # The producer platform is observed, not a portable ABI guarantee. Verify
    # the installed loader and all dynamic dependencies on this exact host.
    linkage = runner(["ldd", str(binary)])
    if "not found" in linkage or "ld-linux-x86-64.so.2" not in linkage:
        raise ValueError("public-key helper loader or dependency is unavailable")
    smoke = subprocess.run(
        [str(binary)], input=b"not a PEM", capture_output=True, check=False, timeout=10
    )
    if (
        smoke.returncode != 1
        or smoke.stdout
        or smoke.stderr.strip() != b"public key is not a supported SPKI PEM"
    ):
        raise ValueError("public-key helper runtime smoke failed")
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer-attestations", action="store_true", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if SHA.fullmatch(args.source_sha) is None or RUN_ID.fullmatch(args.run_id) is None:
        parser.error("producer identity is invalid")
    receipt_path = args.directory / "selfhost-public-kms-jwk.json"
    binary = args.directory / "public-kms-jwk"
    if (
        args.directory.is_symlink()
        or not args.directory.is_dir()
        or receipt_path.is_symlink()
        or not receipt_path.is_file()
        or not 0 < receipt_path.stat().st_size <= 4096
        or any(
            (args.directory / name).is_symlink()
            or not (args.directory / name).is_file()
            for name in (BINARY_BUNDLE, RECEIPT_BUNDLE)
        )
    ):
        parser.error("producer receipt is absent")
    receipt = parsed(receipt_path.read_text(encoding="utf-8"), "receipt")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != EXPECTED_FIELDS
        or receipt != record(binary, args.source_sha, args.run_id)
    ):
        parser.error("producer receipt differs from exact helper")
    verify_subject_attestations(
        binary, receipt_path, args.source_sha, args.run_id, command
    )


if __name__ == "__main__":
    main()
