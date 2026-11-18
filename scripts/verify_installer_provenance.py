"""Verify local installer subjects with bootstrap-pinned verifier executables.

Uses the public-KMS helper's gh bundle/certificate admission pattern. This does
not establish release eligibility or successful acceptance. Callers own the
private staging directory, authenticate verifier binaries before calling, and
must consume the same subject bytes after verification without concurrent writers.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

REPOSITORY = "ElevenID/marty-ui"
REPOSITORY_ID = "1140864197"
ISSUER = "https://token.actions.githubusercontent.com"
REF = "refs/heads/main"
MAX_OUTPUT = 4 * 1024 * 1024
Run = Callable[[list[str]], str]


def command(args: list[str]) -> str:
    """Never inherit authentication, proxy credentials, or verifier overrides."""
    with tempfile.TemporaryDirectory(prefix="marty-installer-verifier-") as home:
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
        environment.update(HOME=home, USERPROFILE=home, GH_CONFIG_DIR=home,
                           XDG_CONFIG_HOME=home, XDG_CACHE_HOME=home,
                           GH_PROMPT_DISABLED="1", GH_HOST="github.com")
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False,
                                    timeout=120, env=environment, cwd=home)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("installer provenance verifier failed") from None
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
        raise ValueError("installer provenance verifier failed")
    return result.stdout


def local_file(path: Path, *, maximum: int | None = None, private: bool = False) -> None:
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("verifier inputs must be absolute non-symlink files")
    try:
        info = path.stat()
    except OSError:
        raise ValueError("verifier input is unavailable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or (maximum and info.st_size > maximum):
        raise ValueError("invalid verifier input file")
    # Windows callers must establish equivalent ACL privacy. Production installer
    # qualification is Linux-only; these checks do not claim Windows support.
    if private and os.name == "posix":
        parent = path.parent.stat()
        if info.st_uid != os.getuid() or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("installer staging directory is not private")
        if info.st_mode & 0o022:
            raise ValueError("installer subject is writable by another user")


def verified_certificate(output: str, *, workflow: str, source_sha: str,
                         run_id: int, run_attempt: int) -> None:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate verifier field")
            result[key] = value
        return result

    if not isinstance(output, str) or len(output) > MAX_OUTPUT:
        raise ValueError("invalid verifier output")
    try:
        result = json.loads(output, object_pairs_hook=pairs)
        if not isinstance(result, list) or len(result) != 1:
            raise ValueError("expected one verified attestation")
        item = result[0]
        if not isinstance(item.get("attestation"), dict):
            raise ValueError("missing verified attestation")
        certificate = item["verificationResult"]["signature"]["certificate"]
        expected = {
            "issuer": ISSUER,
            "runInvocationURI": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}",
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
            "sourceRepositoryDigest": source_sha,
            "sourceRepositoryRef": REF,
            "sourceRepositoryIdentifier": REPOSITORY_ID,
            "buildSignerURI": f"https://github.com/{REPOSITORY}/{workflow}@{REF}",
        }
        if not isinstance(certificate, dict) or any(certificate.get(k) != v for k, v in expected.items()):
            raise ValueError("certificate identity differs")
        # Reject inconsistent legacy fields when a verifier includes both sets.
        for key, value in {"githubWorkflowRepository": REPOSITORY,
                           "githubWorkflowSHA": source_sha, "githubWorkflowRef": REF}.items():
            if key in certificate and certificate[key] != value:
                raise ValueError("legacy certificate identity differs")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("installer attestation identity is invalid") from None


def verify_subject(subject: Path, bundle: Path, *, gh: Path, workflow: str,
                   source_sha: str, run_id: int, run_attempt: int,
                   cosign: Path | None = None, signature_bundle: Path | None = None,
                   runner: Run = command) -> None:
    """Authenticate exact subject bytes and producer invocation; no subject execution.

    Supply cosign and signature_bundle together for separately signed payloads.
    The gh bundle must be the local SLSA bundle, not a URL or API lookup.
    """
    if (not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
            or not isinstance(workflow, str)
            or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", workflow)
            or type(run_id) is not int or run_id <= 0
            or type(run_attempt) is not int or run_attempt <= 0):
        raise ValueError("invalid expected installer identity")
    if (cosign is None) != (signature_bundle is None):
        raise ValueError("cosign verifier and signature bundle are required together")
    for path in (subject, bundle):
        local_file(path, private=True, maximum=4 * 1024 * 1024 if path == bundle else None)
    local_file(gh)
    output = runner([str(gh), "attestation", "verify", str(subject), "--bundle", str(bundle),
                     "--repo", REPOSITORY, "--signer-workflow", f"{REPOSITORY}/{workflow}",
                     "--source-ref", REF, "--source-digest", source_sha,
                     "--deny-self-hosted-runners", "--predicate-type",
                     "https://slsa.dev/provenance/v1", "--format", "json"])
    verified_certificate(output, workflow=workflow, source_sha=source_sha,
                         run_id=run_id, run_attempt=run_attempt)
    if cosign is not None and signature_bundle is not None:
        local_file(cosign)
        local_file(signature_bundle, private=True, maximum=4 * 1024 * 1024)
        runner([str(cosign), "verify-blob", str(subject), "--bundle", str(signature_bundle),
                "--certificate-identity", f"https://github.com/{REPOSITORY}/{workflow}@{REF}",
                "--certificate-oidc-issuer", ISSUER])
