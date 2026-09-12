"""Frozen state-reference guards; importing these requires no capture dependencies."""

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "direct_state_capture", ROOT / "scripts/capture_didcomm_direct_state_reference.py"
)
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)
RAW = (ROOT / CAPTURE.REFERENCE_PATH).read_text(encoding="utf-8")
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
    CAPTURE.validate_reference(REFERENCE)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda ref: ref["cases"].pop(),
        lambda ref: ref["cases"].reverse(),
        lambda ref: ref["cases"][0].update(status=400),
        lambda ref: ref["cases"][1].update(body={"detail": "unavailable"}),
        lambda ref: ref["cases"][0].update(lookup_calls=0),
        lambda ref: ref["cases"][0].update(delivery_calls=1),
        lambda ref: ref["cases"][0].update(extra=True),
        lambda ref: ref["reference"].update(source_blob="0" * 40),
        lambda ref: ref["reference"].update(source_commit="0" * 40),
        lambda ref: ref.update(schema="unrecognized"),
    ],
)
def test_reference_drift_is_rejected(mutation):
    reference = copy.deepcopy(REFERENCE)
    mutation(reference)
    with pytest.raises(AssertionError):
        CAPTURE.validate_reference(reference)


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
                assert f'"../../../../{CAPTURE.REFERENCE_PATH}"' in body
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


def test_source_failure_and_wrong_blob_are_closed(monkeypatch):
    for code, body in [(1, b""), (0, b"different source")]:
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=code, stdout=body)

        monkeypatch.setattr(CAPTURE.subprocess, "run", run)
        with pytest.raises(ValueError):
            CAPTURE.read_sources(Path("controlled-checkout"))
        args, kwargs = calls[0]
        assert args == [
            "git",
            "-C",
            "controlled-checkout",
            "show",
            f"{CAPTURE.SOURCE_COMMIT}:{CAPTURE.SOURCES['routes'][0]}",
        ]
        assert kwargs["timeout"] == 30
        assert kwargs["stderr"] == CAPTURE.subprocess.DEVNULL


def test_ast_selection_preserves_body_and_defaults():
    source = (
        "@router.post('/path')\nasync def didcomm_deliver(x=3):\n    return x + 1\n"
    )
    original = ast.parse(source).body[0]
    original.decorator_list = []
    selected = CAPTURE.selected_definitions(source, ["didcomm_deliver"]).body[1]
    assert ast.dump(selected) == ast.dump(original)
    with pytest.raises(AssertionError):
        CAPTURE.selected_definitions(source, ["missing"])


@pytest.mark.parametrize("check", [False, True])
def test_existing_cli_and_additive_check(monkeypatch, capsys, check):
    monkeypatch.setattr(CAPTURE, "capture", lambda _path: REFERENCE["cases"])
    monkeypatch.setattr(
        CAPTURE.sys, "argv", ["capture", str(ROOT), *(["--check"] if check else [])]
    )
    CAPTURE.main()
    output = capsys.readouterr().out
    if check:
        assert output.startswith("PASS: five pinned direct-state observations")
    else:
        assert json.loads(output) == REFERENCE["cases"]


def test_check_rejects_different_observation(monkeypatch):
    monkeypatch.setattr(CAPTURE, "capture", lambda _path: [])
    monkeypatch.setattr(CAPTURE.sys, "argv", ["capture", str(ROOT), "--check"])
    with pytest.raises(AssertionError, match="observations differ"):
        CAPTURE.main()
