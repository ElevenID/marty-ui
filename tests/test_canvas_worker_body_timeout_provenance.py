"""Actual local-input hash helper: newline portability without JSON rewriting."""

import hashlib
import importlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("run_canvas_worker_body_timeout_oracle")


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n", b"\r"])
def test_local_input_hash_normalizes_only_universal_newlines(
    runner, tmp_path, line_ending
):
    source = '{"score":90.0,"count":90}\n# Résumé π 日本語\n'
    path = tmp_path / "synthetic-input.txt"
    path.write_bytes(source.encode("utf-8").replace(b"\n", line_ending))
    assert (
        runner.capture_input_sha256(path)
        == hashlib.sha256(source.encode("utf-8")).hexdigest()
    )


@pytest.mark.parametrize(
    "changed",
    [
        '{"score":90,"name":"Résumé"}\n',
        '{"score":90.0, "name":"Résumé"}\n',
        '{"score":90.0,"name":"Resume"}\n',
        '{"score":90.0,"name":"Résumé"}',
    ],
)
def test_nonnewline_content_and_numeric_spelling_remain_significant(
    runner, tmp_path, changed
):
    original = '{"score":90.0,"name":"Résumé"}\n'
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_bytes(original.encode("utf-8"))
    after.write_bytes(changed.encode("utf-8"))
    assert runner.capture_input_sha256(before) != runner.capture_input_sha256(after)


def test_invalid_utf8_is_not_silently_replaced(runner, tmp_path):
    path = tmp_path / "invalid.txt"
    path.write_bytes(b"synthetic-\xff\r\n")
    with pytest.raises(UnicodeDecodeError):
        runner.capture_input_sha256(path)


def test_local_hash_reads_text_but_keeps_installed_factory_hash_raw(
    runner, monkeypatch
):
    reads = []

    class LocalInput:
        def read_text(self, *, encoding):
            reads.append(encoding)
            return "numeric = 90.0\n"

        def read_bytes(self):
            pytest.fail("Local capture provenance must use normalized UTF-8 text")

    assert (
        runner.capture_input_sha256(LocalInput())
        == hashlib.sha256(b"numeric = 90.0\n").hexdigest()
    )
    assert reads == ["utf-8"]

    # This is an integration seam, not source substring evidence: fail the raw
    # installed factory pin while making any accidental normalized hash match.
    monkeypatch.setattr(runner, "worker_source_sha256", lambda: runner.SOURCE_SHA256)
    monkeypatch.setattr(
        runner, "published_log_source_sha256", lambda: runner.LOG_SOURCE_SHA256
    )
    monkeypatch.setattr(
        runner, "capture_input_sha256", lambda _: runner.HTTP_SOURCE_SHA256
    )
    monkeypatch.setattr(Path, "read_bytes", lambda _: b"changed immutable factory\r\n")
    with pytest.raises(AssertionError, match="Unexpected published HTTP factory"):
        runner.verify_sources(
            {"source_sha256": runner.SOURCE_SHA256}, ROOT / "contracts"
        )
