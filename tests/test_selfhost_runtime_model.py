"""Keep stage A attached to actual generated/extracted bundle acceptance."""

from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = "rust/crates/selfhost-bundle/tests/executable_bundle.rs"
SHARED = "rust/crates/selfhost-bundle/tests/support/extracted_bundle.rs"
ADAPTER = "rust/crates/selfhost-bundle/tests/support/resolved_selfhost_runtime.rs"
NAME = (
    "actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references"
)


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def compact(value):
    return re.sub(r"\s+", "", value)


def assert_connected(reader):
    source = reader(EXECUTABLE)
    matches = re.findall(
        rf"(?P<attributes>(?:^#\[[^\n]*\]\s*)+)^fn {NAME}\(\) \{{(?P<body>.*?)^\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert len(matches) == 1
    attributes, body = matches[0]
    assert attributes.strip() == "#[test]"
    assert "return" not in body
    assert (
        '#[path = "support/resolved_selfhost_runtime.rs"]\nmod resolved_selfhost_runtime;'
        in source
    )
    assert body.count("resolved_selfhost_runtime::qualify(&repo, &extracted);") == 1
    assert body.index("ExtractedBundle::create(&repo, command())") < body.index(
        "resolved_selfhost_runtime::qualify"
    )
    shared = reader(SHARED)
    assert "ZipArchive::new" in shared
    assert "assert_contained_references(&extracted, &rendered)" in shared
    adapter = reader(ADAPTER)
    for required in [
        "marty_selfhost_bundle::process::compose",
        "ClosedSelfhostModel::from_rendered(&expected, actual, &secret_directory)",
        "negative_controls(model, &expected, secret_directory, &endpoints)",
        "let prepared = prepare(repo, extracted)",
        "normalize_model(raw_model.clone(), extracted)",
        "prepared.verify_sources()",
        "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE",
        "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be",
        '"docker-compose.selfhost.prod.yml", "docker-compose.selfhost.bundle.override.yml"',
        '&["docker-compose.yml"]',
        "self.source_hashes, hashes(&self.source_root)",
    ]:
        assert compact(required) in compact(adapter)
    workflow = reader(".github/workflows/ci.yml")
    assert "cargo test --locked --workspace" in workflow
    assert "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s" in workflow
    assert "install-compose-renderer.sh" in workflow


def test_actual_extracted_runtime_model_is_mandatory():
    assert_connected(read)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "ignored",
        "disconnected",
        "module",
        "fake-render",
        "no-negatives",
        "no-source",
        "no-extracted",
        "pin",
        "export",
        "workspace",
    ],
)
def test_disconnected_or_weakened_runtime_model_gate_refuses(fault):
    def changed(name):
        source = read(name)
        if name == EXECUTABLE:
            if fault == "missing":
                return source.replace(f"fn {NAME}", "fn absent")
            if fault == "ignored":
                return source.replace(f"fn {NAME}", f"#[ignore]\nfn {NAME}")
            if fault == "disconnected":
                return source.replace(
                    "resolved_selfhost_runtime::qualify(&repo, &extracted);", ""
                )
            if fault == "module":
                return source.replace("mod resolved_selfhost_runtime;", "")
        if name == ADAPTER:
            for key, original in {
                "fake-render": "marty_selfhost_bundle::process::compose",
                "no-negatives": "negative_controls(model, &expected, secret_directory, &endpoints)",
                "no-source": '"docker-compose.selfhost.prod.yml", "docker-compose.selfhost.bundle.override.yml"',
                "no-extracted": '&["docker-compose.yml"]',
                "pin": "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be",
            }.items():
                if fault == key:
                    return compact(source).replace(compact(original), "absent")
        if name == ".github/workflows/ci.yml":
            if fault == "export":
                return source.replace(
                    "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s", "ABSENT=%s"
                )
            if fault == "workspace":
                return source.replace(
                    "cargo test --locked --workspace", "cargo test -p marty-gateway"
                )
        return source

    with pytest.raises(AssertionError):
        assert_connected(changed)
