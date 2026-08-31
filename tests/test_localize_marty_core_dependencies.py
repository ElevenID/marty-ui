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


def test_shared_service_image_is_a_rust_only_runtime() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    runtime = dockerfile.split("FROM debian:bookworm-slim", maxsplit=1)[1]
    for marker in (
        "python",
        "pip",
        "requirements-services",
        "MARTY_RS_URI",
        "MARTY_COMMON_URI",
        "COPY services /app/services",
        "COPY packages",
    ):
        assert marker not in runtime
    assert "COPY services/entrypoint.sh /app/services/entrypoint.sh" in runtime
    assert runtime.count("COPY --from=rust-service-builder") == dockerfile.count(
        " --bin marty-"
    )


def test_shared_service_image_provisions_private_writable_runtime_state() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    provision = "install -d -o appuser -g appuser -m 0700 /app/data"
    assert provision in dockerfile
    assert dockerfile.index(provision) < dockerfile.index("USER 10001:10001")


def test_migration_image_preserves_released_wheel_filename() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile.migrations").read_text(encoding="utf-8")

    assert 'MARTY_COMMON_WHEEL="/tmp/${MARTY_COMMON_URI##*/}"' in dockerfile
    assert "pip install --no-cache-dir" in dockerfile
    assert '"$MARTY_COMMON_WHEEL"' in dockerfile
    assert "/tmp/marty-common.whl" not in dockerfile


def test_shared_service_image_does_not_rebuild_external_sources() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "WORKDIR /build/marty-credentials" not in dockerfile
    assert "localize_marty_core_dependencies.py" not in dockerfile
