"""Closed launch contracts; no container inspection, shell or worker execution."""

from pathlib import Path

import pytest

from scripts.canvas_worker_runtime import (
    DISPATCHER,
    NATIVE_LOADER,
    NATIVE_WORKER,
    PYTHON_LOADER,
    classify_worker_launch,
)


@pytest.mark.parametrize("empty", [None, []])
@pytest.mark.parametrize("entry", [False, True])
def test_direct_native_launch_preserves_null_and_empty_vectors(empty, entry):
    args = ([NATIVE_WORKER], empty) if entry else (empty, [NATIVE_WORKER])
    assert classify_worker_launch(*args, {}) == "native"


@pytest.mark.parametrize("selector", ["canvas-sync-worker", "canvas_sync_worker"])
def test_dispatcher_and_exact_loader_resolve_database_template_but_direct_does_not(
    selector,
):
    env = {"SERVICE_NAME": selector, "DATABASE_URL_TEMPLATE": "synthetic-template"}
    assert classify_worker_launch(None, [NATIVE_WORKER], env) is None
    assert classify_worker_launch(None, [DISPATCHER], env) == "native"
    assert classify_worker_launch(["/bin/sh", "-c"], [NATIVE_LOADER], env) == "native"
    # Bind the positive to the real shared dispatcher's loader-before-dispatch.
    source = (
        Path(__file__).resolve().parents[1] / "services/entrypoint.sh"
    ).read_text()
    assert source.index(". /app/load-secrets-env.sh") < source.index(
        "marty-canvas-sync-worker"
    )


@pytest.mark.parametrize(
    "key",
    [
        "ISSUANCE_API_KEY_FILE",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        "INTEGRATION_SECRET_MASTER_KEY_FILE",
        "SSL_CERT_FILE",
        "TOKEN_HMAC_KEY_FILE",
    ],
)
def test_direct_native_does_not_reject_supported_or_unrelated_file_settings(key):
    # Classification does not read any file or claim that unrelated settings are
    # worker dependencies. In particular TOKEN_HMAC_KEY_FILE is preserved only.
    assert (
        classify_worker_launch(None, [NATIVE_WORKER], {key: "/synthetic/file"})
        == "native"
    )


def test_native_secret_file_support_is_bound_to_actual_startup_readers():
    source = (
        Path(__file__).resolve().parents[1]
        / "rust/services/issuance/src/bin/canvas_sync_worker.rs"
    ).read_text()
    for preferred, fallback in [
        ("ISSUANCE_API_KEY", "SIGNING_KEYS_INTERNAL_API_KEY"),
        ("SIGNING_KEYS_INTERNAL_API_KEY", "ISSUANCE_API_KEY"),
    ]:
        assert f'required_secret_with_fallback("{preferred}", "{fallback}")?' in source
    fallback_reader = source.split("fn required_secret_with_fallback(", 1)[1].split(
        "\nfn ", 1
    )[0]
    assert "optional_secret(preferred)?" in fallback_reader
    assert "optional_secret(fallback)" in fallback_reader
    file_reader = source.split("fn optional_secret(", 1)[1].split("\nfn ", 1)[0]
    assert 'format!("{name}_FILE")' in file_reader
    assert "fs::read_to_string(path)?" in file_reader
    master_reader = source.split("fn integration_master_key(", 1)[1].split("\nfn ", 1)[
        0
    ]
    assert 'env::var("INTEGRATION_SECRET_MASTER_KEY_FILE")' in master_reader
    assert "fs::read_to_string(path.trim())?" in master_reader
    env = {
        f"{name}_FILE": "/synthetic/file"
        for name in (
            "ISSUANCE_API_KEY",
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "INTEGRATION_SECRET_MASTER_KEY",
        )
    }
    env.update(
        SSL_CERT_FILE="/synthetic/ca", TOKEN_HMAC_KEY_FILE="/synthetic/preserved"
    )
    assert classify_worker_launch(None, [NATIVE_WORKER], env) == "native"


@pytest.mark.parametrize(
    "entry,command",
    [
        (None, ["python", "-m", "issuance.canvas_worker"]),
        ([], ["python3", "-m", "issuance.canvas_worker"]),
        (["/bin/sh", "-c"], [PYTHON_LOADER]),
    ],
)
def test_historical_python_rollback_launch_remains_recognized(entry, command):
    assert (
        classify_worker_launch(
            entry, command, {"CANVAS_SYNC_PROCESSOR": "module:callback"}
        )
        == "python"
    )


@pytest.mark.parametrize(
    "env",
    [
        [],
        None,
        {1: "private-value"},
        {"SERVICE_NAME": []},
        {"SERVICE_NAME": "issuance_native"},
        {"CANVAS_SYNC_PROCESSOR": "module:callback"},
    ],
)
def test_native_selection_rejects_wrong_selector_callback_or_malformed_environment(env):
    assert classify_worker_launch(None, [NATIVE_WORKER], env) is None


@pytest.mark.parametrize(
    "entry,command",
    [
        (["/bin/bash", "-c"], [NATIVE_LOADER]),
        (["/bin/sh", "-lc"], [NATIVE_LOADER]),
        (["/bin/sh", "-c"], [NATIVE_LOADER + "echo private-value\n"]),
        (["/bin/sh", "-c"], [NATIVE_LOADER.rstrip()]),
        (["/bin/sh", "-c"], [NATIVE_LOADER.replace("\n", "\r\n")]),
        (None, [NATIVE_WORKER, "--private-value"]),
        (None, NATIVE_WORKER),
        ([NATIVE_WORKER], ["private-value"]),
        (None, [DISPATCHER]),
    ],
)
def test_arbitrary_or_incomplete_launch_is_not_native(entry, command):
    assert classify_worker_launch(entry, command, {}) is None
