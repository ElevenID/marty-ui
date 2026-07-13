from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from localize_marty_core_dependencies import localize_manifest  # noqa: E402


def test_localizer_accepts_any_pinned_revision_and_preserves_features(tmp_path: Path) -> None:
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(
        """[workspace]
[workspace.dependencies]
marty-crypto = { git = "https://github.com/ElevenID/marty-core.git", rev = "0123456789abcdef", features = ["sod-builder"] }
marty-verification = { git = "https://github.com/ElevenID/marty-core.git", rev = "fedcba9876543210" }
marty-oid4vci = { git = "https://github.com/ElevenID/marty-core.git", rev = "aaaaaaaaaaaaaaaa" }
""",
        encoding="utf-8",
    )

    localized = localize_manifest(manifest, "../marty-core")
    parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
    dependencies = parsed["workspace"]["dependencies"]

    assert localized == ["marty-crypto", "marty-verification", "marty-oid4vci"]
    assert dependencies["marty-crypto"] == {
        "path": "../marty-core/marty-crypto",
        "features": ["sod-builder"],
    }
    assert dependencies["marty-verification"]["path"] == "../marty-core/marty-verification"
    assert dependencies["marty-oid4vci"]["path"] == "../marty-core/marty-oid4vci"


def test_localizer_rejects_unexpected_dependency_source(tmp_path: Path) -> None:
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(
        """[workspace]
[workspace.dependencies]
marty-crypto = { git = "https://example.com/not-marty-core.git", rev = "abc" }
""",
        encoding="utf-8",
    )

    try:
        localize_manifest(manifest, "../marty-core")
    except ValueError as error:
        assert "must be pinned" in str(error)
    else:
        raise AssertionError("Unexpected dependency source must be rejected")


def test_shared_service_image_includes_external_issuance_runtime_dependencies() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY marty-credentials/services/issuance /app/services/issuance" in dockerfile
    assert "COPY marty-credentials/python/status_list /app/status_list" in dockerfile


def test_shared_service_image_builds_the_document_verification_bindings() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "WORKDIR /build/marty-credentials/rust/marty-rs" in dockerfile
    assert "localize_marty_core_dependencies.py" in dockerfile
