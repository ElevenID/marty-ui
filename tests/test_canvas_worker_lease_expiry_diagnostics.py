"""Closed diagnostic reporting only; no worker, database or parity execution."""

import importlib
import io
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("test_canvas_worker_lease_expiry_https")


def test_every_rust_category_matches_closed_parser_inventory(native):
    source = (
        ROOT
        / "rust/services/issuance/tests/support/canvas_worker_lease_expiry_replay.rs"
    ).read_text(encoding="utf-8")
    block = re.search(r"enum Diagnostic \{([^}]+)\}", source).group(1)
    categories = re.findall(r"^\s*([A-Za-z]+),\s*$", block, re.MULTILINE)
    assert len(categories) == len(set(categories)) == 33
    assert {name.encode() for name in categories} == native.DIAGNOSTIC_CATEGORIES
    mapping = re.search(
        r"fn failure_diagnostic\(reason: &str\) -> Diagnostic \{(.*?)\n\}\n",
        source,
        re.DOTALL,
    )
    mapped_reasons = re.findall(r'"(native expiry [^"\n]+)"', mapping.group(1))
    actual_checks = source[mapping.end() :].split("#[cfg(test)]")[0]
    assert len(mapped_reasons) == 19
    assert all(f'"{reason}"' in actual_checks for reason in mapped_reasons)
    for name in categories:
        contents = (
            b"private panic payload\n"
            + native.DIAGNOSTIC_PREFIX
            + name.encode()
            + b"\nprivate token suffix\n"
        )
        assert native.coordinator_diagnostics(io.BytesIO(contents)) == (
            "Native expiry coordinator diagnostics: " + name
        )


@pytest.mark.parametrize(
    "contents,classification",
    [
        (b"", "unavailable"),
        (b"private-secret", "unavailable"),
        (b"MARTY_TIMEOUT_DIAG_V1:Complete\n", "unavailable"),
        (b"MARTY_EXPIRY_DIAG_V1:private-secret\n", "invalid"),
        (b"MARTY_EXPIRY_DIAG_V1:LockHeld", "invalid"),
        (b"MARTY_EXPIRY_DIAG_V1:LockHeld private-secret\n", "invalid"),
        (b"private-secret MARTY_EXPIRY_DIAG_V1:LockHeld\n", "invalid"),
        (b"MARTY_EXPIRY_DIAG_V1:LockHeld\v\n", "invalid"),
        (b"MARTY_EXPIRY_DIAG_V1:LockHeld\n" * 2, "invalid"),
        (
            b"MARTY_EXPIRY_DIAG_V1:LockHeld\nMARTY_EXPIRY_DIAG_V1:private-secret\n",
            "invalid",
        ),
        (b"MARTY_EXPIRY_DIAG_V1:LockHeld\n" + b"x" * 65536, "oversized"),
    ],
    ids=[
        "empty",
        "private-only",
        "other-family",
        "unknown-category",
        "truncated",
        "suffix",
        "embedded-prefix",
        "non-newline-separator",
        "duplicate",
        "mixed-valid-invalid",
        "oversized",
    ],
)
def test_malformed_or_private_records_never_become_notes(
    native, contents, classification
):
    result = native.coordinator_diagnostics(io.BytesIO(contents))
    assert result == f"Native expiry coordinator diagnostics {classification}"
    assert "private-secret" not in result


def test_record_limit_does_not_truncate_into_apparent_valid_evidence(native):
    categories = sorted(native.DIAGNOSTIC_CATEGORIES)
    contents = b"".join(
        native.DIAGNOSTIC_PREFIX + value + b"\n" for value in categories
    )
    assert native.coordinator_diagnostics(io.BytesIO(contents)) == (
        "Native expiry coordinator diagnostics invalid"
    )
    contents = b"".join(
        native.DIAGNOSTIC_PREFIX + value + b"\n" for value in categories[:32]
    )
    assert native.coordinator_diagnostics(io.BytesIO(contents)) == (
        "Native expiry coordinator diagnostics: "
        + ",".join(value.decode() for value in categories[:32])
    )


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_bounded_reader_and_whole_line_ending(native, ending):
    class Reader(io.BytesIO):
        def read(self, size=-1):
            assert size == 65537
            return super().read(size)

    stream = Reader(b"MARTY_EXPIRY_DIAG_V1:FailureUnknown" + ending)
    stream.seek(0, 2)
    assert native.coordinator_diagnostics(stream).endswith(": FailureUnknown")


@pytest.mark.parametrize("failure", ["seek", "read", "wrong-type"])
def test_failed_reader_returns_only_static_note(native, failure):
    class Reader(io.BytesIO):
        def seek(self, *args):
            if failure == "seek":
                raise OSError("private-reader-secret")
            return super().seek(*args)

        def read(self, *_args):
            if failure == "read":
                raise ValueError("private-reader-secret")
            return "private-reader-secret"

    assert native.coordinator_diagnostics(Reader()) == (
        "Native expiry coordinator diagnostics unavailable"
    )


def test_invalid_parser_family_cannot_echo_supplied_name(native):
    assert (
        native.header.coordinator_diagnostics(
            io.BytesIO(), family="private-family-secret"
        )
        == "Native coordinator diagnostics invalid"
    )
