"""Fail-closed policy for the central Rust feature-regression probe inputs."""

from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / ".github" / "feature-regression" / "rust-probe"
MANIFEST = PROBE / "Cargo.toml"
LOCK = PROBE / "Cargo.lock"
SUBJECT = PROBE / "behavior_subject.rs"


def test_probe_uses_only_the_reserved_regular_files() -> None:
    assert {path.name for path in PROBE.iterdir() if not path.name == "target"} == {
        "Cargo.lock",
        "Cargo.toml",
        "behavior_subject.rs",
    }
    for path in (MANIFEST, LOCK, SUBJECT):
        assert path.is_file()
        assert not path.is_symlink()


def test_probe_manifest_has_one_fixed_binary_and_real_candidate_dependency() -> None:
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["bin"] == [
        {
            "name": "elevenid-feature-regression-probe",
            "path": "behavior_subject.rs",
            "test": False,
        }
    ]
    assert manifest["dependencies"]["marty-issuance-service"] == {
        "path": "../../../rust/services/issuance"
    }
    assert manifest["patch"]["crates-io"] == {
        "isomdl": {
            "git": "https://github.com/ElevenID/isomdl-elevenid",
            "rev": "671044c9495aec101bf0cd381669d5ed6f64dd11",
        },
        "ssi-jwt": {"path": "../../../rust/third_party/ssi-jwt"},
    }

    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    root_package = next(
        package
        for package in lock["package"]
        if package["name"] == "elevenid-feature-regression-probe"
    )
    assert "marty-issuance-service" in root_package["dependencies"]
    assert (
        "marty_issuance_service::internal_application_domain::"
        "derive_applicant_identifier"
    ) in SUBJECT.read_text(encoding="utf-8")


def test_ci_runs_the_frozen_offline_probe_twice_and_compares_exact_output() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert "Verify frozen Rust feature-regression probe" in workflow
    assert 'cargo fetch --locked --manifest-path "$manifest"' in workflow
    assert workflow.count("cargo run --frozen --offline --quiet \\") == 2
    assert "cargo test --frozen --offline --quiet \\" in workflow
    assert "cmp --silent \"$first_output\" \"$second_output\"" in workflow
    assert "json.dumps(document, ensure_ascii=False, sort_keys=True" in workflow
