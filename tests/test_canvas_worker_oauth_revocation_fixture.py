"""Revocation harness integrity controls, not application parity evidence."""

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_revocation_matrix_retains_transport_and_cleanup_inputs():
    root = Path(__file__).resolve().parents[1]
    matrix = json.loads(
        (root / "contracts/canvas-worker-oauth-revocation-scenarios.json").read_text()
    )
    cases = matrix["cases"]
    assert len(cases) == len({case["name"] for case in cases}) == 7
    assert [case["status"] for case in cases] == [200, 204, 404, 429, 503, 302, 200]
    assert cases[-1]["hold_response"] is True
    assert cases[3]["delay_bounds"] == [37, 37]
    assert all(case["delay_bounds"] == [30, 37] for case in cases[4:])
    assert len(matrix["additional_secrets"]) == 2
    assert {secret[1] for secret in matrix["additional_secrets"]} == {
        "org-review",
        "org-other",
    }


@pytest.mark.parametrize("names,reference", [(["a", "a"], {"a": {}}), (["a"], {})])
def test_native_owner_rejects_duplicate_or_missing_reference_cases(
    monkeypatch, names, reference
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    inputs = iter(
        [
            json.dumps({"cases": [{"name": name} for name in names]}),
            json.dumps(reference),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    monkeypatch.setattr(
        native,
        "WorkerHttpsFixture",
        lambda: pytest.fail("invalid matrix must fail before fixture creation"),
    )
    with pytest.raises(AssertionError):
        native.run("synthetic-not-executed")


@pytest.mark.parametrize("failure", ["child_exit", "timeout", "wrong_requests"])
def test_native_owner_fails_closed_and_closes_https(monkeypatch, tmp_path, failure):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    inputs = iter(
        [
            json.dumps({"cases": [{"name": "synthetic"}]}),
            json.dumps({"synthetic": {"requests": [{"method": "DELETE"}]}}),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    closed = []

    class Fixture:
        def __enter__(self):
            return SimpleNamespace(
                certificates=SimpleNamespace(name=str(tmp_path)),
                cert=tmp_path / "synthetic-cert",
                origin="https://127.0.0.1:1",
                requests=[],
            )

        def __exit__(self, *_):
            closed.append(True)

    def child(*_, **kwargs):
        assert kwargs["timeout"] == 240
        if failure == "timeout":
            raise native.subprocess.TimeoutExpired("synthetic-owned-child", 240)
        return SimpleNamespace(
            returncode=1 if failure == "child_exit" else 0, stdout="", stderr=""
        )

    monkeypatch.setattr(native, "WorkerHttpsFixture", Fixture)
    monkeypatch.setattr(native.subprocess, "run", child)
    with pytest.raises((AssertionError, native.subprocess.TimeoutExpired)):
        native.run("synthetic-not-executed")
    assert closed == [True]
