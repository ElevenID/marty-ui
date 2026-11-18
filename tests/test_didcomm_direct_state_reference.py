"""Frozen state-reference guards; importing these requires no capture dependencies."""

import hashlib
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATH = "contracts/didcomm-direct-state-python-reference.json"
RAW = (ROOT / REFERENCE_PATH).read_text(encoding="utf-8")
REFERENCE = json.loads(RAW)
RUST_TESTS = {
    "rust/services/issuance/src/initiation_didcomm.rs": (
        "ineligible_states_match_captured_python_without_downstream_effects",
        "eligible_states_continue_through_delivery_after_state_parity",
        "durable_delivery_dispatch_precedes_ineligible_transaction_state",
    ),
    "rust/services/issuance/tests/didcomm_delivery_behavior.rs": (
        "direct_didcomm_ineligible_states_match_captured_python_responses",
    ),
}


def test_original_artifact_is_unchanged():
    assert hashlib.sha256(RAW.encode()).hexdigest() == (
        "19d6a6ea5a8adfdd9e07fb61a91a417427c5474193d92474dc585a78ee7ea891"
    )


def assert_connected(root):
    for relative, names in RUST_TESTS.items():
        source = (root / relative).read_text(encoding="utf-8")
        for name in names:
            matches = re.findall(
                rf"(?P<attrs>(?:^[ \t]*#\[[^\n]*\]\s*)+)"
                rf"^[ \t]*async fn {name}\(\) \{{(?P<body>.*?)^[ \t]*\}}",
                source,
                re.MULTILINE | re.DOTALL,
            )
            assert len(matches) == 1, name
            attrs, body = matches[0]
            assert attrs.strip() == "#[tokio::test]", name
            assert body.strip(), name
            if "captured_python" in name:
                assert f'"../../../../{REFERENCE_PATH}"' in body
    manifest = (root / "rust/services/issuance/Cargo.toml").read_text(encoding="utf-8")
    assert 'path = "tests/didcomm_delivery_behavior.rs"' in manifest
    assert "cargo test --locked --workspace" in (
        root / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")


def test_rust_and_required_ci_remain_connected():
    assert_connected(ROOT)


@pytest.mark.parametrize(
    "relative",
    [
        "rust/services/issuance/src/initiation_didcomm.rs",
        "rust/services/issuance/tests/didcomm_delivery_behavior.rs",
        "rust/services/issuance/Cargo.toml",
        ".github/workflows/ci.yml",
    ],
)
def test_disconnected_gate_is_rejected(monkeypatch, relative):
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path == ROOT / relative:
            return "disconnected"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        assert_connected(ROOT)


@pytest.mark.parametrize("mutation", ["ignored", "cfg-disabled", "missing-body"])
@pytest.mark.parametrize(
    "relative,name",
    [(path, name) for path, names in RUST_TESTS.items() for name in names],
)
def test_disabled_named_test_is_rejected(monkeypatch, relative, name, mutation):
    original = Path.read_text

    def read(path, *args, **kwargs):
        source = original(path, *args, **kwargs)
        if path != ROOT / relative:
            return source
        marker = f"async fn {name}() {{"
        if mutation == "missing-body":
            return source.replace(marker, f"async fn removed_{name}() {{")
        attr = "#[ignore]" if mutation == "ignored" else "#[cfg(any())]"
        return source.replace(marker, f"{attr}\n{marker}")

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        assert_connected(ROOT)
