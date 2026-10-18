"""Exercise preparation dispatch and evidence without building or provisioning."""

import builtins
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def probe(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "recovery_preparation_probe",
        ROOT / "scripts/probe_integration_secret_coordinated_restore.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    binary = (
        tmp_path
        / "rust/target/debug"
        / ("marty-signing-keys.exe" if os.name == "nt" else "marty-signing-keys")
    )
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"not an executable; must never run")
    evidence = tmp_path / "timing.jsonl"
    monkeypatch.setenv("MARTY_RECOVERY_PREPARATION_TIMING_FILE", str(evidence))
    return module, evidence, binary


def expected_commands():
    prefix = ["cargo", "+1.95.0"]
    return [
        prefix
        + [mode, "--locked", "-p", package]
        + selection
        + (["--no-run"] if mode == "test" else [])
        + ["-j", "1"]
        for mode, package, selection in [
            ("build", "marty-signing-keys", ["--bin", "marty-signing-keys"]),
            ("test", "marty-signing-keys", ["--test", "vc_api_holder_proof_live_kms"]),
            ("test", "marty-issuance-service", ["--lib"]),
            (
                "test",
                "marty-issuance-service",
                ["--test", "canvas_oauth_postgres_contract"],
            ),
            ("test", "marty-issuance-service", ["--test", "didcomm_remote_kms_live"]),
            ("test", "marty-flow", ["--test", "haip_live_signing"]),
            ("test", "marty-flow", ["--test", "haip_remote_http"]),
            ("test", "marty-flow", ["--test", "haip_expired_http"]),
        ]
    ]


def test_prepare_only_uses_all_eight_unchanged_commands_and_no_services(
    probe, monkeypatch
):
    module, evidence, binary = probe
    calls, progress = [], []

    def forbidden(*args, **kwargs):
        pytest.fail("prepare-only must not provision or run the full qualification")

    def execute(command, **kwargs):
        assert kwargs == {"cwd": module.ROOT / "rust", "timeout": 1800, "check": False}
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    def printed(*args, **kwargs):
        progress.append((args[0], kwargs.get("flush")))
        builtins.print(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", execute)
    monkeypatch.setattr(module, "print", printed, raising=False)
    for name in ("run", "docker", "prepare_image", "with_disposable_tls_kms"):
        monkeypatch.setattr(module, name, forbidden)
    module.main(["--prepare-rust-only"])
    assert calls == expected_commands()
    assert binary.read_bytes().startswith(b"not an executable")
    assert len(progress) == 16 and all(flushed for _, flushed in progress)
    rows = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [row["phase"] for row in rows] == list(module.RUST_PREPARATION_PHASES)
    assert all(row["status"] == "ok" and row["duration_ms"] >= 0 for row in rows)
    assert all(
        set(row) == {"schema_version", "phase", "status", "duration_ms"} for row in rows
    )


@pytest.mark.parametrize(
    "fault, status", [("failed", "failed"), ("timeout", "timeout"), ("spawn", "error")]
)
def test_failed_preparation_flushes_final_record_and_stops(
    probe, monkeypatch, capsys, fault, status
):
    module, evidence, _ = probe
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if len(calls) == 2:
            if fault == "timeout":
                raise subprocess.TimeoutExpired(command, 1800, output="private-payload")
            if fault == "spawn":
                raise OSError("private-payload")
            return subprocess.CompletedProcess(command, 9)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module.subprocess, "run", execute)
    with pytest.raises(RuntimeError) as error:
        module.build_rust()
    assert calls == expected_commands()[:2]
    rows = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [row["status"] for row in rows] == ["ok", status]
    assert (
        "private-payload"
        not in capsys.readouterr().out + str(error.value) + evidence.read_text()
    )


def test_default_cli_retains_full_qualification(probe, monkeypatch):
    module, _, _ = probe
    calls = []
    monkeypatch.setattr(module, "run", lambda: calls.append("full"))
    monkeypatch.setattr(
        module, "build_rust", lambda: pytest.fail("default must call the full owner")
    )
    module.main([])
    assert calls == ["full"]


def test_optional_evidence_failure_never_replaces_build_result(
    probe, monkeypatch, capsys
):
    module, evidence, binary = probe
    monkeypatch.setenv(
        "MARTY_RECOVERY_PREPARATION_TIMING_FILE", str(evidence / "missing-parent")
    )
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )
    assert module.build_rust() == binary
    assert "optional timing artifact unavailable" in capsys.readouterr().out


def test_unknown_labels_cannot_enter_public_timing(probe):
    module, _, _ = probe
    with pytest.raises(ValueError, match="Unknown recovery"):
        module.record_preparation_timing("private-payload", "ok", 0)
    with pytest.raises(ValueError, match="Unknown recovery"):
        module.record_preparation_timing(
            module.RUST_PREPARATION_PHASES[0], "private-payload", 0
        )


def test_optional_cache_evidence_uses_shared_sanitizer_and_fixed_labels(
    probe, monkeypatch
):
    module, _, _ = probe
    cache_file = module.ROOT / "cache.jsonl"
    monkeypatch.setenv("MARTY_RECOVERY_PREPARATION_CACHE_FILE", str(cache_file))
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        if command[0] == "sccache":
            return subprocess.CompletedProcess(
                command, 0, stdout="Cache hits (Rust)  7\nprivate-path secret"
            )
        assert command[:4] == ["awk", "-v", "phase=recovery_probe", "-f"]
        assert command[4] == str(module.ROOT / "scripts/ci/public-sccache-stats.awk")
        assert kwargs["input"] == "Cache hits (Rust)  7\nprivate-path secret"
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='MARTY_PUBLIC_SCCACHE_V1 {"phase":"recovery_probe","counters":{"cache_hits_rust":7}}\n',
        )

    monkeypatch.setattr(module.subprocess, "run", execute)
    module.record_preparation_cache("signing_keys_binary")
    assert [command[0] for command, _ in calls] == ["sccache", "awk"]
    assert all(kwargs["timeout"] == 10 and kwargs["check"] is False for _, kwargs in calls)
    assert json.loads(cache_file.read_text()) == {
        "schema_version": 1,
        "phase": "signing_keys_binary",
        "counters": {"cache_hits_rust": 7},
    }
    assert "private-path" not in cache_file.read_text()


def test_optional_cache_counter_allowlist_matches_shared_sanitizer(probe):
    module, _, _ = probe
    sanitizer = (ROOT / "scripts/ci/public-sccache-stats.awk").read_text()
    labels = set(re.findall(r'labels\[[^]]+\] = "([^"]+)"', sanitizer))
    assert labels == module.PUBLIC_CACHE_COUNTERS


def test_optional_cache_records_baseline_and_each_unchanged_phase(probe, monkeypatch):
    module, _, binary = probe
    cache_file = module.ROOT / "cache.jsonl"
    monkeypatch.setenv("MARTY_RECOVERY_PREPARATION_CACHE_FILE", str(cache_file))
    cargo_calls = []

    def execute(command, **kwargs):
        if command[0] == "cargo":
            cargo_calls.append(command)
            return subprocess.CompletedProcess(command, 0)
        if command[0] == "sccache":
            return subprocess.CompletedProcess(command, 0, stdout="Cache hits (Rust)  1\n")
        assert command[0] == "awk"
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                'MARTY_PUBLIC_SCCACHE_V1 {"phase":"recovery_probe",'
                f'"counters":{{"cache_hits_rust":{len(cargo_calls)}}}}}\n'
            ),
        )

    monkeypatch.setattr(module.subprocess, "run", execute)
    assert module.build_rust() == binary
    assert cargo_calls == expected_commands()
    rows = [json.loads(line) for line in cache_file.read_text().splitlines()]
    assert [row["phase"] for row in rows] == list(module.CACHE_SNAPSHOT_PHASES)
    assert [row["counters"]["cache_hits_rust"] for row in rows] == list(range(9))


@pytest.mark.parametrize(
    "sanitized",
    [
        "",
        'MARTY_PUBLIC_SCCACHE_V1 []',
        'MARTY_PUBLIC_SCCACHE_V1 {"phase":"wrong","counters":{"cache_hits_rust":7}}',
        'MARTY_PUBLIC_SCCACHE_V1 {"phase":"recovery_probe","counters":{"secret":"payload"}}',
        'MARTY_PUBLIC_SCCACHE_V1 {"phase":"recovery_probe","counters":{"cache_hits_rust":"7"}}',
    ],
)
def test_optional_cache_evidence_rejects_missing_or_unsafe_counters(
    probe, monkeypatch, sanitized
):
    module, _, _ = probe
    cache_file = module.ROOT / "cache.jsonl"
    monkeypatch.setenv("MARTY_RECOVERY_PREPARATION_CACHE_FILE", str(cache_file))

    def execute(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="raw private-path" if command[0] == "sccache" else sanitized,
        )

    monkeypatch.setattr(module.subprocess, "run", execute)
    module.record_preparation_cache("issuance_library")
    assert not cache_file.exists()


def test_optional_cache_failure_cannot_replace_build_result(probe, monkeypatch, capsys):
    module, _, binary = probe
    cache_file = module.ROOT / "cache.jsonl"
    monkeypatch.setenv("MARTY_RECOVERY_PREPARATION_CACHE_FILE", str(cache_file))
    cargo_calls = []

    def execute(command, **kwargs):
        if command[0] == "sccache":
            raise subprocess.TimeoutExpired(command, 10, output="private-payload")
        cargo_calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module.subprocess, "run", execute)
    assert module.build_rust() == binary
    assert cargo_calls == expected_commands()
    assert not cache_file.exists()
    assert "private-payload" not in capsys.readouterr().out
    with pytest.raises(ValueError, match="Unknown recovery"):
        module.record_preparation_cache("private-payload")


def test_workflow_retains_tiny_failure_evidence_without_weakening_recovery():
    job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"][
        "test-openbao-didcomm-plugin"
    ]
    steps = {step.get("name"): step for step in job["steps"]}
    recovery = steps[
        "Qualify Rust integration-secret recovery with coordinated PostgreSQL and Raft restore"
    ]
    assert (
        recovery["run"]
        == "python3 scripts/probe_integration_secret_coordinated_restore.py"
    )
    assert (
        not recovery.get("continue-on-error")
        and "--prepare-rust-only" not in recovery["run"]
    )
    assert (
        recovery["env"]["CARGO_PROFILE_DEV_DEBUG"]
        == recovery["env"]["CARGO_PROFILE_TEST_DEBUG"]
        == 0
    )
    assert recovery["env"]["CARGO_INCREMENTAL"] == 0
    assert recovery["env"]["MARTY_RECOVERY_PREPARATION_CACHE_FILE"] == (
        "${{ runner.temp }}/rust-recovery-preparation-cache.jsonl"
    )
    assert job["env"]["SCCACHE_GHA_RW_MODE"] == "READ_ONLY"
    cache = steps["Record optional recovery compiler cache outcomes"]
    assert (
        cache["if"] == "always()"
        and "timeout 10s sccache --show-stats 2>/dev/null" in cache["run"]
    )
    assert (
        "awk -v phase=recovery_probe -f scripts/ci/public-sccache-stats.awk"
        in cache["run"]
    )
    retained = steps["Retain recovery preparation evidence"]
    assert retained["if"] == "always()"
    assert retained["continue-on-error"] is True
    assert (
        retained["uses"]
        == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert retained["with"]["retention-days"] == 7
    assert retained["with"]["path"].splitlines() == [
        "${{ runner.temp }}/rust-recovery-preparation.jsonl",
        "${{ runner.temp }}/rust-recovery-preparation-cache.jsonl",
        "${{ runner.temp }}/rust-recovery-cache-counters.jsonl",
    ]


def test_host_rust_ci_and_warmer_share_fast_debug_settings():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    warmer = yaml.safe_load(
        (ROOT / ".github/workflows/warm-ci-caches.yml").read_text()
    )["jobs"]["rust"]
    lint = next(
        job for job in jobs.values() if job.get("name") == "Rust Lint and Packaging"
    )
    for job in (jobs["test-rust-services"], lint, warmer):
        assert job["env"]["CARGO_PROFILE_DEV_DEBUG"] == 0
        assert job["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
        assert job["env"]["CARGO_INCREMENTAL"] == 0
    assert warmer["timeout-minutes"] == 30
    assert warmer["env"]["SCCACHE_GHA_RW_MODE"] == "READ_WRITE"
    assert (
        jobs["test-rust-services"]["env"]["SCCACHE_GHA_RW_MODE"]
        == lint["env"]["SCCACHE_GHA_RW_MODE"]
        == "READ_ONLY"
    )
