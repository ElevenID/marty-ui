"""Keep the extracted fast owner and retained signing boundaries explicitly mapped."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.ci import check_python_value_fast_obligations as guard

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads(
    (ROOT / "contracts/python-value-fast-obligations.json").read_text(encoding="utf-8")
)


def test_current_source_and_targets_match_bounded_inventory() -> None:
    guard.validate(MANIFEST)
    assert len(MANIFEST["cases"]) == 4
    assert len(MANIFEST["retained_signing_detail"]["tests"]) == 12
    assert len(MANIFEST["retained_http"]["tests"]) == 7
    assert all(
        case["cheapest_proving_layer"] == "pure unit" for case in MANIFEST["cases"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "missing_unit",
        "duplicate_unit",
        "missing_assertion",
        "missing_oracle_role",
        "wrong_owner",
        "missing_unicode_input",
        "missing_signing_case",
        "wrong_http_case",
    ],
)
def test_inventory_drift_fails_closed(change: str) -> None:
    manifest = deepcopy(MANIFEST)
    if change == "missing_unit":
        manifest["cases"].pop()
    elif change == "duplicate_unit":
        manifest["cases"][1]["test"] = manifest["cases"][0]["test"]
    elif change == "missing_assertion":
        manifest["cases"][0]["assertion"] = ""
    elif change == "missing_oracle_role":
        manifest["cases"][0]["oracle_role"] = ""
    elif change == "wrong_owner":
        manifest["owner"]["package"] = "marty-issuance-service"
    elif change == "missing_unicode_input":
        manifest["owner"]["common_inputs"].remove(
            "contracts/python-text-semantics.json"
        )
    elif change == "missing_signing_case":
        manifest["retained_signing_detail"]["tests"].pop()
    else:
        manifest["retained_http"]["tests"][0] = "signing_http_response::tests::unknown"
    with pytest.raises(ValueError):
        guard.validate(manifest)


@pytest.mark.parametrize(
    "attribute",
    [
        "#[ignore]",
        '#[ignore = "reason"]',
        '#[cfg(feature = "slow")]',
        '#[cfg_attr(feature = "slow", ignore)]',
    ],
)
def test_ignored_or_feature_conditional_test_is_not_counted_active(
    attribute: str,
) -> None:
    with pytest.raises(ValueError, match="Conditional or ignored"):
        guard.declared_tests(f"{attribute}\n#[test]\nfn owned() {{}}")
    with pytest.raises(ValueError, match="Conditional or ignored"):
        guard.declared_tests(f"#[test]\n{attribute}\nfn owned() {{}}")


def test_commented_test_attribute_is_not_discovered() -> None:
    assert guard.declared_tests("// #[test]\nfn not_a_test() {}") == set()
    with pytest.raises(ValueError, match="attribute/function"):
        guard.declared_tests("#[test]\n// fn hidden() {}")


@pytest.mark.parametrize(
    "path,needle",
    [
        ("rust/crates/response-compat/src/lib.rs", "pub mod python_value;"),
        (
            "rust/services/issuance/tests/signing_error_detail_contract.rs",
            '#[path = "../src/signing_error_detail.rs"]',
        ),
        ("rust/services/issuance/src/lib.rs", "mod signing_error_detail;"),
        (
            "rust/services/issuance/src/signing_http_response.rs",
            '#[path = "signing_http_response_tests.rs"]',
        ),
    ],
)
def test_commented_out_module_wiring_fails_closed(
    monkeypatch: pytest.MonkeyPatch, path: str, needle: str
) -> None:
    actual_source = guard.source

    def altered_source(root: Path, source_path: str) -> str:
        text = actual_source(root, source_path)
        if source_path == path:
            assert needle in text
            return text.replace(needle, f"// {needle}", 1)
        return text

    monkeypatch.setattr(guard, "source", altered_source)
    with pytest.raises(ValueError, match="drift"):
        guard.validate(MANIFEST)


@pytest.mark.parametrize(
    "path,old,new",
    [
        (
            "rust/crates/response-compat/src/python_value.rs",
            "#[cfg(test)]\nmod tests {",
            '#[cfg(all(test, feature = "postgres"))]\nmod tests {',
        ),
        (
            "rust/services/issuance/Cargo.toml",
            'path = "tests/signing_error_detail_contract.rs"',
            'path = "tests/signing_error_detail_contract.rs"\nrequired-features = ["postgres"]',
        ),
    ],
)
def test_feature_gate_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch, path: str, old: str, new: str
) -> None:
    actual_source = guard.source

    def altered_source(root: Path, source_path: str) -> str:
        text = actual_source(root, source_path)
        if source_path == path:
            assert old in text
            return text.replace(old, new, 1)
        return text

    monkeypatch.setattr(guard, "source", altered_source)
    with pytest.raises(ValueError, match="feature gate drift"):
        guard.validate(MANIFEST)


def test_raw_string_cannot_fake_http_module_wiring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_source = guard.source
    target = "rust/services/issuance/src/signing_http_response.rs"
    path_attribute = '#[path = "signing_http_response_tests.rs"]'

    def altered_source(root: Path, source_path: str) -> str:
        text = actual_source(root, source_path)
        if source_path == target:
            assert path_attribute in text
            fake = (
                'const FAKE: &str = r#"\n#[cfg(test)]\n'
                '#[path = "signing_http_response_tests.rs"]\n'
                'pub(crate) mod tests;\n"#;\n'
            )
            return fake + text.replace(path_attribute, f"// {path_attribute}", 1)
        return text

    monkeypatch.setattr(guard, "source", altered_source)
    with pytest.raises(ValueError, match="HTTP test module wiring drift"):
        guard.validate(MANIFEST)
