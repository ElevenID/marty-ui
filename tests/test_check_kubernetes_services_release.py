"""A Kubernetes selector must bind to the signed Rust-only release digest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.check_kubernetes_services_release import validate
from tests.test_prepare_official_beta_release import (
    _manifest, _write_release, SERVICES_DIGEST,
)


SOURCE = "1" * 40
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@" + SERVICES_DIGEST


def release(tmp_path: Path) -> Path:
    manifest = _manifest()
    manifest["components"] = [item for item in manifest["components"]
                              if item["name"] != "marty-credentials-issuance"]
    path, _ = _write_release(tmp_path, manifest)
    return path


def rewrite(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (path.parent / "SHA256SUMS").write_text(
        f"{digest}  stack-manifest.json\n", encoding="utf-8")


def test_exact_signed_rust_release_binds_kubernetes_services_image(tmp_path: Path) -> None:
    path = release(tmp_path)
    calls = []

    def attest(manifest_path, images, commit):
        calls.append((manifest_path, images, commit))
        return True

    assert validate(path, IMAGE, SOURCE, attest=attest) == IMAGE
    assert calls == [(path, {
        "ghcr.io/elevenid/marty-ui-oss/ui": "sha256:" + "a" * 64,
        "ghcr.io/elevenid/marty-ui-oss/services": SERVICES_DIGEST,
        "ghcr.io/elevenid/marty-ui-oss/migrations": "sha256:" + "c" * 64,
    }, SOURCE)]


@pytest.mark.parametrize("reference", [
    "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "f" * 64,
    "ghcr.io/elevenid/marty-ui-oss/services:latest",
    "docker.io/elevenid/marty-ui-oss/services@" + SERVICES_DIGEST,
    "ghcr.io/other/services@" + SERVICES_DIGEST,
])
def test_unbound_or_mutable_image_is_refused(tmp_path: Path, reference: str) -> None:
    path = release(tmp_path)
    with pytest.raises(ValueError, match="signed Rust-only"):
        validate(path, reference, SOURCE, attest=lambda *_: True)


def test_signed_release_from_different_checkout_is_refused(tmp_path: Path) -> None:
    path = release(tmp_path)
    with pytest.raises(ValueError, match="signed Rust-only"):
        validate(path, IMAGE, "f" * 40, attest=lambda *_: True)


def test_legacy_issuance_or_unverified_attestation_is_refused(tmp_path: Path) -> None:
    path = release(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["components"].append(_manifest()["components"][7])
    rewrite(path, manifest)
    with pytest.raises(ValueError, match="signed Rust-only"):
        validate(path, IMAGE, SOURCE, attest=lambda *_: True)

    path = release(tmp_path)
    with pytest.raises(ValueError, match="signed Rust-only"):
        validate(path, IMAGE, SOURCE, attest=lambda *_: False)


def test_mismatched_checksum_and_duplicate_json_key_are_refused(tmp_path: Path) -> None:
    path = release(tmp_path)
    (path.parent / "SHA256SUMS").write_text("0" * 64 + "  stack-manifest.json\n")
    with pytest.raises(ValueError, match="signed Rust-only"):
        validate(path, IMAGE, SOURCE, attest=lambda *_: True)

    path = release(tmp_path)
    path.write_text(path.read_text().replace(
        '"schema": "marty.stack/v1",',
        '"schema": "marty.stack/v1", "schema": "marty.stack/v1",', 1),
        encoding="utf-8")
    with pytest.raises(ValueError, match="signed Rust-only"):
        validate(path, IMAGE, SOURCE, attest=lambda *_: True)
