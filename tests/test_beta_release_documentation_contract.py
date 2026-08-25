"""Keep beta instructions on the immutable aggregate Rust release path."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "BETA_RELEASES.md"
QUICK_START = ROOT / "QUICK_START.md"
README = ROOT / "README.md"


def test_beta_guide_names_the_current_aggregate_gates() -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    prose = " ".join(guide.split())

    assert "former per-repository Python-wheel beta process is retired" in prose
    for workflow in ("cd.yml", "e2e-tests.yml", "wallet-conformance.yml"):
        assert f".github/workflows/{workflow}" in guide
        assert (ROOT / ".github" / "workflows" / workflow).is_file()

    for environment in (
        "stack-release",
        "beta-lifecycle",
        "wallet-conformance",
    ):
        assert environment in guide


def test_retired_python_beta_trigger_does_not_return() -> None:
    guide = GUIDE.read_text(encoding="utf-8").lower()

    assert "pip install" not in guide
    assert "marty-microservices-framework==" not in guide
    assert not (ROOT / "scripts" / "trigger-beta-builds.sh").exists()


def test_quick_start_does_not_advertise_retired_source_mounts() -> None:
    guide = QUICK_START.read_text(encoding="utf-8")

    assert "Mounted sibling repositories in dev mode" not in guide
    assert "/app/marty-microservices-framework" not in guide
    assert "do not mount sibling source repositories" in guide


def test_readme_names_immutable_rust_runtime_inputs() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "shared Rust crate platform" in readme
    assert "immutable OCI image" in readme
    assert "do not mount sibling source repositories" in readme
    assert "Packages are mounted as volumes" not in readme
    assert "installed from GitHub Packages registry" not in readme
