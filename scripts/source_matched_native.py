"""Authenticate a native helper against its digest, build identity and checkout."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import subprocess


def verified_native_binary(root: Path, prefix: str) -> Path | None:
    if prefix not in {"MARTY_DEPLOY", "MARTY_CI_EXECUTION"}:
        raise ValueError("Unsupported native tool")
    binary = os.environ.get(f"{prefix}_BIN", "").strip()
    if not binary:
        return None
    expected_sha = os.environ.get(f"{prefix}_BIN_SHA256", "").strip().lower()
    source_sha = os.environ.get(f"{prefix}_SOURCE_SHA", "").strip()
    release_tag = os.environ.get(f"{prefix}_RELEASE_TAG", "").strip()
    if not expected_sha:
        raise RuntimeError(f"{prefix}_BIN_SHA256 is required")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise RuntimeError(f"{prefix}_BIN_SHA256 is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise RuntimeError(f"{prefix}_SOURCE_SHA is required and must be valid")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-nightly\.20[0-9]{6}\.[1-9][0-9]*)?", release_tag):
        raise RuntimeError(f"{prefix}_RELEASE_TAG is required and must be valid")
    binary_path = Path(binary)
    if not binary_path.is_file():
        raise RuntimeError(f"{prefix}_BIN is not a file")
    with binary_path.open("rb") as handle:
        actual_sha = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError(f"{prefix}_BIN digest mismatch")
    identity = subprocess.run(
        [str(binary_path), "--build-identity"],
        check=False, capture_output=True, text=True,
    )
    if identity.returncode != 0 or identity.stdout.strip() != f"{source_sha}:{release_tag}":
        raise RuntimeError(f"{prefix}_BIN source or tag mismatch")
    if (root / ".git").exists():
        checkout = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
            check=False, capture_output=True, text=True,
        )
        if checkout.returncode != 0 or checkout.stdout.strip() != source_sha:
            raise RuntimeError(f"{prefix}_BIN source differs from checkout HEAD")
    return binary_path
