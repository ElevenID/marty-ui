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


def test_shared_service_image_installs_released_credentials_bindings() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "MARTY_RS_URI" in dockerfile
    assert "MARTY_RS_DIGEST" in dockerfile
    assert "curl --fail --location" in dockerfile
    assert "sha256sum --check --strict" in dockerfile
    assert "/tmp/marty-rs.whl" in dockerfile
    assert "COPY marty-credentials" not in dockerfile


def test_shared_service_image_does_not_rebuild_external_sources() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "WORKDIR /build/marty-credentials" not in dockerfile
    assert "localize_marty_core_dependencies.py" not in dockerfile
