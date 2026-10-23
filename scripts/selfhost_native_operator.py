"""Invoke the existing release-authenticated Rust operator, or the source checkout."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess


def operator_command(root: Path, *args: str) -> list[str]:
    binary = os.environ.get("MARTY_DEPLOY_BIN", "").strip()
    if binary:
        expected_sha = os.environ.get("MARTY_DEPLOY_BIN_SHA256", "").strip().lower()
        source_sha = os.environ.get("MARTY_DEPLOY_SOURCE_SHA", "").strip()
        release_tag = os.environ.get("MARTY_DEPLOY_RELEASE_TAG", "").strip()
        if not expected_sha:
            raise RuntimeError("MARTY_DEPLOY_BIN_SHA256 is required")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise RuntimeError("MARTY_DEPLOY_BIN_SHA256 is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
            raise RuntimeError("MARTY_DEPLOY_SOURCE_SHA is required and must be valid")
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release_tag):
            raise RuntimeError("MARTY_DEPLOY_RELEASE_TAG is required and must be valid")
        binary_path = Path(binary)
        if not binary_path.is_file():
            raise RuntimeError("MARTY_DEPLOY_BIN is not a file")
        with binary_path.open("rb") as handle:
            actual_sha = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual_sha != expected_sha:
            raise RuntimeError("MARTY_DEPLOY_BIN digest mismatch")
        identity = subprocess.run(
            [str(binary_path), "--build-identity"],
            check=False, capture_output=True, text=True,
        )
        if identity.returncode != 0 or identity.stdout.strip() != f"{source_sha}:{release_tag}":
            raise RuntimeError("MARTY_DEPLOY_BIN source or tag mismatch")
        if (root / ".git").exists():
            checkout = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
                check=False, capture_output=True, text=True,
            )
            if checkout.returncode != 0 or checkout.stdout.strip() != source_sha:
                raise RuntimeError("MARTY_DEPLOY_BIN source differs from checkout HEAD")
        command = [str(binary_path), *args] if args[:1] == ("operator",) else [
            str(binary_path), "--repo-root", str(root), *args]
    else:
        if not (root / "rust/Cargo.toml").is_file():
            raise RuntimeError("Install and source the matching signed marty-deploy operator first")
        command = [
            "cargo", "+1.95.0", "run", "--quiet", "--locked",
            "--manifest-path", str(root / "rust/Cargo.toml"),
            "-p", "marty-deployment-catalog", "--bin", "marty-deploy",
            "--", *(["--repo-root", str(root)] if args[:1] != ("operator",) else []), *args,
        ]
    return command


def operator_bytes(root: Path, *args: str, input: bytes | None = None) -> bytes:
    timeout = 10 if os.environ.get("MARTY_DEPLOY_BIN") and args[1:2] != ("check-snapshot",) else 300
    result = subprocess.run(operator_command(root, *args), input=input,
                            capture_output=True, check=False, timeout=timeout)
    if result.returncode:
        # Native commands use fixed diagnostics; never echo public input or tokens.
        raise RuntimeError("Rust operator validation failed")
    return result.stdout
