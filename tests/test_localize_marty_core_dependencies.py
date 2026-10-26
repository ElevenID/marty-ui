from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from localize_marty_core_dependencies import (  # noqa: E402
    localize_manifest,
    localize_manifests,
    plan_localization,
)


def make_core(root: Path, packages: dict[str, str]) -> Path:
    root.mkdir()
    root.joinpath("Cargo.toml").write_text(
        "[workspace]\nmembers = " + repr(list(packages)).replace("'", '\"') + "\n"
    )
    for directory, name in packages.items():
        target = root / directory
        target.mkdir(parents=True)
        target.joinpath("Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.2.2"\n'
        )
    return root


def test_localizer_accepts_any_pinned_revision_and_preserves_features(tmp_path: Path) -> None:
    make_core(tmp_path / "marty-core", {
        "crypto": "marty-crypto", "verify": "marty-verification", "oid": "marty-oid4vci",
    })
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "Cargo.toml"
    manifest.write_text(
        """[workspace]
[workspace.dependencies]
marty-crypto = { git = "https://github.com/ElevenID/marty-core.git", rev = "0123456789abcdef", version = "=0.2.2", features = ["kms-only"], default-features = false }
marty-verification = { git = "https://github.com/ElevenID/marty-core", rev = "fedcba9876543210" }
marty-oid4vci = { git = "https://github.com/ElevenID/marty-core", rev = "aaaaaaaaaaaaaaaa" }
""",
        encoding="utf-8",
    )
    localized = localize_manifest(manifest, "../marty-core")
    dependencies = tomllib.loads(manifest.read_text())["workspace"]["dependencies"]
    assert set(localized) == {"marty-crypto", "marty-verification", "marty-oid4vci"}
    assert dependencies["marty-crypto"] == {
        "path": "../marty-core/crypto", "version": "=0.2.2",
        "features": ["kms-only"], "default-features": False,
    }
    assert dependencies["marty-verification"]["path"] == "../marty-core/verify"
    assert dependencies["marty-oid4vci"]["path"] == "../marty-core/oid"


def test_localizer_rejects_unexpected_dependency_source(tmp_path: Path) -> None:
    import pytest
    core = make_core(tmp_path / "core", {"crypto": "marty-crypto"})
    manifest = tmp_path / "Cargo.toml"
    original = '[dependencies]\nmarty-crypto = { git = "https://example.com/not-marty-core.git", rev = "abc" }\n'
    manifest.write_text(original)
    with pytest.raises(ValueError, match="No dependencies pinned"):
        localize_manifests([manifest], core)
    assert manifest.read_text() == original


def test_all_workspace_members_aliases_target_dependencies_and_excluded_crypto_patch_are_localized(tmp_path: Path) -> None:
    core = make_core(tmp_path / "core", {"crypto-source": "marty-crypto", "emrtd-source": "marty-emrtd-issuance"})
    vendor = core / "third_party" / "curve"
    vendor.mkdir(parents=True)
    vendor.joinpath("Cargo.toml").write_text('[package]\nname="elliptic-curve"\nversion="0.13.8"\n')
    with core.joinpath("Cargo.toml").open("a") as handle:
        handle.write('[patch.crates-io]\nelliptic-curve={path="third_party/curve"}\n')
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "Cargo.toml"
    other = 'ssi = { git = "https://github.com/ElevenID/ssi-elevenid", rev = "keep", default-features = false }'
    manifest.write_text("""[workspace]
members=["issuance"]
[workspace.dependencies]
crypto_alias={package="marty-crypto",version="=0.2.2",git="https://github.com/ElevenID/marty-core",branch="dev",features=["kms-only"],default-features=false}
""" + other + '\n[patch.crates-io]\ncurve_alias={package="elliptic-curve",git="https://github.com/ElevenID/marty-core.git",rev="old"}\n')
    child = project / "issuance"
    child.mkdir()
    child.joinpath("Cargo.toml").write_text("""[package]
name="issuer"
version="0.1.0"
[target.'cfg(windows)'.build-dependencies.emrtd_alias]
package="marty-emrtd-issuance"
git="https://github.com/ElevenID/marty-core"
tag="old"
optional=true
features=["one", "two"]
""")
    result = localize_manifests([manifest], core)
    assert set(result) == {"crypto_alias", "curve_alias", "emrtd_alias"}
    assert other in manifest.read_text()
    parsed = tomllib.loads(child.joinpath("Cargo.toml").read_text())
    assert parsed["target"]["cfg(windows)"]["build-dependencies"]["emrtd_alias"] == {
        "package":"marty-emrtd-issuance", "optional":True,
        "features":["one", "two"], "path":"../../core/emrtd-source",
    }
    assert "third_party/curve" in manifest.read_text()


def test_complete_plan_failure_cannot_partially_rewrite_earlier_manifest(tmp_path: Path) -> None:
    import pytest
    core = make_core(tmp_path / "core", {"crypto": "marty-crypto"})
    manifests = []
    for directory, name in [("first", "marty-crypto"), ("second", "missing")]:
        p = tmp_path / directory
        p.mkdir()
        manifest = p / "Cargo.toml"
        manifest.write_text('[dependencies]\nitem={package="' + name + '",git="https://github.com/ElevenID/marty-core",rev="old"}\n')
        manifests.append(manifest)
    before = [p.read_bytes() for p in manifests]
    with pytest.raises(ValueError, match="Missing Core package"):
        localize_manifests(manifests, core)
    assert [p.read_bytes() for p in manifests] == before


def test_multiline_dry_run_preserves_metadata_and_every_non_source_field(tmp_path: Path) -> None:
    core = make_core(tmp_path / "core", {"crypto": "marty-crypto"})
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text("""[package.metadata.dependencies]
ignored={git="https://github.com/ElevenID/marty-core",rev="keep"}
[dev-dependencies]
alias={package="marty-crypto", git="https://github.com/ElevenID/marty-core", rev="old", version="0.2", features=[
  "kms-only"
], default-features=false, optional=true}
""")
    before = manifest.read_bytes()
    localize_manifests([manifest], core, dry_run=True)
    assert manifest.read_bytes() == before
    plan, _ = plan_localization([manifest], core)
    after = tomllib.loads(plan[manifest.resolve()][1].decode())
    assert after["package"]["metadata"]["dependencies"]["ignored"]["rev"] == "keep"
    assert after["dev-dependencies"]["alias"] == {
        "package":"marty-crypto", "version":"0.2", "features":["kms-only"],
        "default-features":False, "optional":True, "path":"core/crypto",
    }


def test_ambiguous_core_package_is_rejected_before_any_write(tmp_path: Path) -> None:
    import pytest
    core = make_core(tmp_path / "core", {"one": "duplicate", "two": "duplicate"})
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text('[dependencies]\none={package="duplicate",git="https://github.com/ElevenID/marty-core"}\n')
    original = manifest.read_bytes()
    with pytest.raises(ValueError, match="Ambiguous Core package"):
        localize_manifests([manifest], core)
    assert manifest.read_bytes() == original


def test_existing_cli_default_is_manifest_relative_from_another_working_directory(tmp_path: Path) -> None:
    import subprocess
    make_core(tmp_path / "marty-core", {"crypto": "marty-crypto"})
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "Cargo.toml"
    manifest.write_text('[dependencies]\ncrypto={package="marty-crypto",git="https://github.com/ElevenID/marty-core",rev="old"}\n')
    elsewhere = tmp_path / "unrelated-cwd"
    elsewhere.mkdir()
    subprocess.run([sys.executable, str(ROOT / "scripts/localize_marty_core_dependencies.py"),
                    str(manifest)], cwd=elsewhere, check=True, capture_output=True, text=True)
    dependency = tomllib.loads(manifest.read_text())["dependencies"]["crypto"]
    assert dependency == {"package":"marty-crypto", "path":"../marty-core/crypto"}


def test_partial_current_write_failure_restores_all_attempted_manifests(tmp_path: Path, monkeypatch) -> None:
    import pytest
    core = make_core(tmp_path / "core", {"crypto": "marty-crypto"})
    manifests = []
    for name in ["first", "second"]:
        directory = tmp_path / name
        directory.mkdir()
        manifest = directory / "Cargo.toml"
        manifest.write_text('[dependencies]\ncrypto={package="marty-crypto",git="https://github.com/ElevenID/marty-core",rev="old"}\n')
        manifests.append(manifest)
    originals = {path:path.read_bytes() for path in manifests}
    write = Path.write_bytes
    failed = False

    def partial_write(path, content):
        nonlocal failed
        if path == manifests[1] and not failed:
            failed = True
            write(path, b"partial current write")
            raise OSError("actual partial write simulation")
        return write(path, content)

    monkeypatch.setattr(Path, "write_bytes", partial_write)
    with pytest.raises(OSError, match="actual partial write simulation"):
        localize_manifests(manifests, core)
    assert failed
    assert {path:path.read_bytes() for path in manifests} == originals


def test_shared_service_image_is_a_rust_only_runtime() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    build_script = (ROOT / "scripts" / "build-rust-service-binaries.sh").read_text(
        encoding="utf-8"
    )

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
    assert runtime.count("COPY --from=rust-service-builder") == build_script.count(
        " --bin marty-"
    )


def test_shared_service_image_provisions_private_writable_runtime_state() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    provision = "install -d -o appuser -g appuser -m 0700 /app/data"
    assert provision in dockerfile
    assert dockerfile.index(provision) < dockerfile.index("USER 10001:10001")


def test_migration_image_contains_only_shared_rust_binaries() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile.migrations").read_text(encoding="utf-8")

    assert "FROM debian:bookworm-slim" in dockerfile
    assert "marty-migration-bootstrap" in dockerfile
    assert "marty-notification" in dockerfile
    assert "COPY contracts/python-text-semantics.json" in dockerfile
    assert "COPY services /app/services" not in dockerfile
    assert "pip install" not in dockerfile


def test_shared_service_image_does_not_rebuild_external_sources() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "WORKDIR /build/marty-credentials" not in dockerfile
    assert "localize_marty_core_dependencies.py" not in dockerfile
