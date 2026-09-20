"""Frozen packager evidence and mandatory executable-gate connections."""

import ast
import hashlib
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "scripts/capture_selfhost_bundle_reference.py"
ARTIFACT = ROOT / "contracts/selfhost-bundle-python-reference.json"
SOURCE = "rust/crates/selfhost-bundle/tests/executable_bundle.rs"
SHARED = "rust/crates/selfhost-bundle/tests/support/extracted_bundle.rs"
NAME = (
    "actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references"
)


def validate_reference(reference):
    constants = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in ast.parse(CAPTURE.read_text(encoding="utf-8")).body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"REVISION", "SOURCE", "BLOB"}
    }
    assert reference["schema"] == "marty.selfhost-bundle-python-reference/v1"
    assert reference["reference"]["revision"] == constants["REVISION"]
    assert reference["reference"]["source"] == constants["SOURCE"]
    assert reference["reference"]["blob"] == constants["BLOB"]
    assert len(reference["cases"]) == 18
    stage = reference["staging"]
    assert stage["archive_files_hex"] == {
        f"bundle/{path}": value for path, value in stage["directory_hex"].items()
    }
    assert stage["archive_directories"] == [
        "bundle/",
        "bundle/config/",
        "bundle/scripts/",
    ]
    assert stage["render_calls"] == [
        {
            "argv": [
                "docker",
                "compose",
                "--env-file",
                ".env.selfhost.production.example",
                "-f",
                "docker-compose.selfhost.prod.yml",
                "-f",
                "docker-compose.selfhost.bundle.override.yml",
                "config",
                "--no-interpolate",
            ],
            "cwd_is_output": True,
        }
    ]


def test_pinned_capture_identity_and_original_archive_contract():
    assert (
        hashlib.sha256(ARTIFACT.read_text(encoding="utf-8").encode()).hexdigest()
        == "160d3a31976297b8a546cda0d0d89e8032a7ed8230bdcfe0b4392d057b3cd331"
    )
    validate_reference(json.loads(ARTIFACT.read_text(encoding="utf-8")))


def assert_path_reference(raw):
    assert (
        hashlib.sha256(raw.encode()).hexdigest()
        == "a33f33c12e0a7953d7b95e30c7987ae8c04e794c54224b84544c11c5b159f6d2"
    )
    reference = json.loads(raw)
    assert reference["schema"] == "marty.selfhost-bundle-path-reference/v1"
    assert (
        reference["packager_source_blob"] == "77c04ba60f7a31432d210526f50e136f6bde0545"
    )
    assert set(reference["stdlib_sources"]) == {
        "pathlib.py",
        "ntpath.py",
        "posixpath.py",
    }
    cases = reference["cases"]
    assert len(cases) == 26
    assert sum(case["platform"] == "windows" for case in cases) == 17
    assert sum(case["platform"] == "posix" for case in cases) == 9


def test_actual_pathlib_expansion_capture_and_native_connection():
    assert_path_reference(read("contracts/selfhost-bundle-path-reference.json"))
    source = read("rust/crates/selfhost-bundle/src/user_path.rs")
    assert (
        "#[test]\n    fn frozen_platform_pathlib_expansion_retains_names_and_errors"
        in source
    )
    assert "contracts/selfhost-bundle-path-reference.json" in source
    assert "mod user_path;" in read("rust/crates/selfhost-bundle/src/main.rs")
    assert "Path.expanduser(path_type(value))" in CAPTURE.read_text(encoding="utf-8")


@pytest.mark.parametrize("fault", ["stdlib", "case", "expanded", "error"])
def test_changed_path_oracle_is_rejected(fault):
    reference = json.loads(read("contracts/selfhost-bundle-path-reference.json"))
    if fault == "stdlib":
        reference["stdlib_sources"]["pathlib.py"] = "0" * 64
    elif fault == "case":
        reference["cases"].pop()
    elif fault == "expanded":
        reference["cases"][0]["expanded"] = "wrong"
    else:
        next(case for case in reference["cases"] if "error" in case)["error"] = "wrong"
    with pytest.raises(AssertionError):
        assert_path_reference(json.dumps(reference, indent=2) + "\n")


@pytest.mark.parametrize("fault", ["blob", "case", "archive", "directory", "render"])
def test_disconnected_reference_is_rejected(fault):
    reference = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    if fault == "blob":
        reference["reference"]["blob"] = "0" * 40
    elif fault == "case":
        reference["cases"].pop()
    elif fault == "archive":
        reference["staging"]["archive_files_hex"].popitem()
    elif fault == "directory":
        reference["staging"]["archive_directories"].pop()
    else:
        reference["staging"]["render_calls"][0]["argv"].pop()
    with pytest.raises(AssertionError):
        validate_reference(reference)


def assert_connections(read):
    executable = read(SOURCE)
    matches = re.findall(
        rf"(?P<attributes>(?:^#\[[^\n]*\]\s*)+)^fn {NAME}\(\) \{{(?P<body>.*?)^\}}",
        executable,
        re.MULTILINE | re.DOTALL,
    )
    assert len(matches) == 1
    attrs, body = matches[0]
    assert attrs.strip() == "#[test]"
    assert "package-selfhost-bundle" in executable
    assert (
        '#[path = "support/extracted_bundle.rs"]\nmod extracted_bundle;' in executable
    )
    assert body.count("ExtractedBundle::create(&repo, command())") == 1
    assert "fixture.verify_unchanged()" in body
    assert "assert_operator_bind_paths(&repo, &extracted)" in body
    helper = read(SHARED)
    assert "inventory(&self.extracted), self.verified_inventory" in helper
    assert "inventory(&self.output), self.verified_inventory" in helper
    assert "#[test]\nfn jointly_mutated_verified_bundle_is_refused()" in helper
    shared = helper.split("pub(super) fn create", 1)[1].split(
        "pub(super) fn directory", 1
    )[0]
    for required in [
        "ZipArchive::new",
        'extraction.join("customer-bundle")',
        "process::compose",
        "validate_strict",
        "assert_descriptor_inventory(repo, &output)",
        "assert_contained_references(&extracted, &rendered)",
        "inventory(&output)",
        "inventory(&extracted)",
    ]:
        assert required in shared
    assert "return" not in body
    assert "return" not in shared
    assert '"crates/selfhost-bundle"' in read("rust/Cargo.toml")
    assert "cargo test --locked --workspace" in read(".github/workflows/ci.yml")
    assert "contracts/selfhost-bundle-python-reference.json" in read(
        "rust/crates/selfhost-bundle/tests/package_contract.rs"
    )
    makefile = read("Makefile")
    assert "--bin package-selfhost-bundle --locked -- --repo-root ." in makefile
    assert "python scripts/package-selfhost-bundle.py" not in makefile


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def test_actual_bundle_gate_runs_in_required_workspace_ci():
    assert_connections(read)


@pytest.mark.parametrize(
    "fault",
    [
        "ignored",
        "cfg-disabled",
        "missing",
        "no-zip",
        "no-render",
        "no-inventory",
        "no-containment",
        "no-operator-binds",
        "shared-disconnected",
        "shared-module",
        "shared-baseline",
        "workspace",
        "make",
    ],
)
def test_disabled_or_shallow_bundle_gate_is_rejected(fault):
    def changed(relative):
        source = read(relative)
        if relative == SOURCE:
            if fault == "ignored":
                return source.replace(f"fn {NAME}", f"#[ignore]\nfn {NAME}")
            if fault == "cfg-disabled":
                return source.replace(f"fn {NAME}", f"#[cfg(any())]\nfn {NAME}")
            if fault == "missing":
                return source.replace(f"fn {NAME}", "fn missing")
            if fault == "shared-disconnected":
                return source.replace(
                    "ExtractedBundle::create(&repo, command())", "absent()"
                )
            if fault == "shared-module":
                return source.replace("mod extracted_bundle;", "")
            if fault == "no-operator-binds":
                return source.replace(
                    "assert_operator_bind_paths(&repo, &extracted)",
                    "absent(&repo, &extracted)",
                )
        if relative == SHARED:
            if fault == "shared-baseline":
                return source.replace(
                    "self.verified_inventory", "inventory(&self.output)"
                )
            if fault == "no-zip":
                return source.replace("ZipArchive::new", "FakeArchive::new")
            if fault == "no-render":
                return source.replace("process::compose", "process::fake")
            if fault == "no-inventory":
                return source.replace(
                    "assert_descriptor_inventory(repo, &output)",
                    "fake_inventory(repo, &output)",
                )
            if fault == "no-containment":
                return source.replace(
                    "assert_contained_references(&extracted, &rendered)",
                    "fake_references(&extracted, &rendered)",
                )
        if fault == "workspace" and relative == "rust/Cargo.toml":
            return source.replace('"crates/selfhost-bundle"', '"absent"')
        if fault == "make" and relative == "Makefile":
            return source.replace("--bin package-selfhost-bundle", "--bin absent")
        return source

    with pytest.raises(AssertionError):
        assert_connections(changed)
