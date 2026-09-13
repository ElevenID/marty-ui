"""Closed oracle guards; explicit capture --check independently executes Python."""

import builtins
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "token_rate_capture", ROOT / "scripts/capture_token_rate_reference.py"
)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def corpus():
    return json.loads((ROOT / capture.ARTIFACT).read_text(encoding="utf-8"))


def case(name):
    return next(row for row in corpus()["cases"] if row["case"] == name)


def test_protected_sources_and_exact_cases_are_closed():
    # Normalize checkout line endings, not JSON fields or observation content.
    artifact = (ROOT / capture.ARTIFACT).read_text(encoding="utf-8").encode("utf-8")
    assert hashlib.sha256(artifact).hexdigest() == (
        "68153d972df0ee5bdaa3dc1b5739764ccdf6c0fb930ace3f773f22486c3f201a"
    )
    frozen = corpus()
    assert frozen["reference"]["source_commit"] == capture.REVISION
    assert {
        path: value["git_blob"]
        for path, value in frozen["reference"]["sources"].items()
    } == capture.SOURCES
    assert len(frozen["cases"]) == 40
    assert [
        {key: row[key] for key in capture.cases()[0]} for row in frozen["cases"]
    ] == capture.cases()
    assert len({row["case"] for row in frozen["cases"]}) == 40
    assert len(frozen["clock_vectors"]) == 15
    for row in frozen["cases"]:
        if row["phase"] == "requests":
            assert (
                len(row["stored_state"])
                == len(row["direct"])
                == len(row["time_bits"])
                == len(row["times"])
                == len(row["http"])
            )


def test_capture_import_does_not_require_retired_runtime_dependencies(monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"httpx", "fastapi", "starlette"}:
            raise AssertionError(
                "Ordinary source guards must not import runtime dependencies"
            )
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    isolated = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(isolated)
    assert isolated.cases() == capture.cases()


def test_platform_clock_is_in_workspace_ci_and_shared_image_without_service_expansion():
    workspace = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))
    assert "crates/platform-clock" in workspace["workspace"]["members"]
    service = tomllib.loads(
        (ROOT / "rust/services/issuance/Cargo.toml").read_text(encoding="utf-8")
    )
    assert service["dependencies"]["marty-platform-clock"] == {
        "path": "../../crates/platform-clock"
    }
    assert service["lints"]["rust"]["unsafe_code"] == "forbid"
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "cargo test --locked --workspace --no-run" in workflow
    assert "cargo test --locked --workspace >" in workflow
    assert "cargo clippy --locked --workspace --all-targets" in workflow
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    assert "COPY rust /build/rust" in dockerfile
    assert "COPY contracts /build/contracts" in dockerfile


@pytest.mark.parametrize("name", ["zero", "negative", "negative-zero"])
def test_nonpositive_limit_is_request_rejection_not_startup_failure(name):
    observed = case(f"limit-{name}")
    assert observed["phase"] == "requests"
    assert (
        observed["direct"]
        == [
            {
                "status": 429,
                "body": {"detail": "Rate limit exceeded"},
                "headers": {"Retry-After": "60"},
            }
        ]
        * 3
    )
    assert all(row["downstream_calls"] == 0 for row in observed["http"])


@pytest.mark.parametrize(
    "name",
    [
        "window-float-overflow",
        "window-negative-float-overflow",
        "overflow-before-zero-limit",
        "overflow-before-negative-limit",
    ],
)
def test_window_overflow_precedes_limit_and_has_closed_real_default_http_boundary(name):
    observed = case(name)
    assert observed["phase"] == "requests"
    assert observed["direct"] == [{"error_type": "OverflowError"}] * 3
    assert (
        observed["http"]
        == [
            {
                "status": 500,
                "body": "Internal Server Error",
                "headers": {"content-type": "text/plain; charset=utf-8"},
                "downstream_calls": 0,
            }
        ]
        * 3
    )


@pytest.mark.parametrize("name", ["limit-malformed-canary", "window-malformed"])
def test_startup_error_projection_never_echoes_raw_configuration(name):
    observed = case(name)
    assert observed["phase"] == "configuration"
    assert observed["error_type"] == "ValueError"
    assert set(observed) == {
        "case",
        "limit",
        "window",
        "times",
        "time_bits",
        "phase",
        "error_type",
    }


def test_nonpositive_and_rounded_window_semantics_are_not_duration_clamps():
    for name in ["window-zero", "window-negative"]:
        assert case(name)["direct"] == [{"allowed": True}] * 3
    assert case("zero-limit-negative-window")["direct"][0]["headers"] == {
        "Retry-After": "-1"
    }
    assert case("zero-limit-huge-window-header")["direct"][0]["headers"] == {
        "Retry-After": "18446744073709551616"
    }
    assert case("rounded-window")["direct"] == [
        {"allowed": True},
        {"allowed": True},
        {
            "status": 429,
            "body": {"detail": "Rate limit exceeded"},
            "headers": {"Retry-After": "9007199254740993"},
        },
    ]


def test_modified_git_blob_is_rejected_before_execution(monkeypatch):
    monkeypatch.setattr(
        capture.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=b"raise AssertionError('must not run')\n"
        ),
    )
    with pytest.raises(ValueError, match="Pinned source identity differs"):
        capture.sources(ROOT)


@pytest.mark.parametrize("source", ["x = 1", "class Owned: pass\nclass Owned: pass"])
def test_missing_or_duplicate_selected_source_is_rejected(source):
    with pytest.raises(ValueError, match="Exact source selection differs"):
        capture.selected(source, "synthetic.py", {"Owned"}, {})
