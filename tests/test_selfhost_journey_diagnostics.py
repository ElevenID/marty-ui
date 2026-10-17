"""Disposable installation diagnostics never become qualification evidence."""

import argparse
import ast
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_selfhost_business_journey as runner  # noqa: E402
import selfhost_journey_diagnostics as diag  # noqa: E402


def test_runner_measurements_match_redacted_diagnostic_phases() -> None:
    tree = ast.parse(Path(runner.__file__).read_text(encoding="utf-8"))
    measured_phases = {
        call.args[1].value
        for call in ast.walk(tree)
        if (isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "measured"
            and len(call.args) == 2
            and isinstance(call.args[1], ast.Constant)
            and isinstance(call.args[1].value, str))
    }
    assert measured_phases == diag.PHASES


def test_memory_parser_requires_complete_kib_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = ("MemTotal: 16384 kB\nMemAvailable: 8192 kB\n"
           "SwapTotal: 4096 kB\nSwapFree: 3072 kB\n")
    monkeypatch.setattr(diag.Path, "read_text", lambda *_args, **_kwargs: raw)
    assert diag.linux_memory() == {
        "MemTotal": 16384 * 1024, "MemAvailable": 8192 * 1024,
        "SwapTotal": 4096 * 1024, "SwapFree": 3072 * 1024,
    }
    monkeypatch.setattr(diag.Path, "read_text", lambda *_args, **_kwargs: raw[:-19])
    with pytest.raises(ValueError, match="incomplete"):
        diag.linux_memory()


def test_first_failure_survives_successful_cleanup_and_excludes_private_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {"MemTotal": 16 * 1024**3, "MemAvailable": 8 * 1024**3,
              "SwapTotal": 4 * 1024**3, "SwapFree": 3 * 1024**3}
    monkeypatch.setattr(diag, "linux_memory", lambda: values)
    diagnostics = diag.RunDiagnostics(tmp_path, interval_seconds=100)
    diagnostics.start()
    with pytest.raises(ValueError, match="private-credential"):
        with diagnostics.measure("public_journey"):
            raise ValueError("private-credential")
    with diagnostics.measure("cleanup"):
        pass
    diagnostics.stop()
    report = diagnostics.report(checks_result="failed")
    assert report["first_failure_phase"] == "public_journey"
    assert [row["status"] for row in report["phases"]] == ["failed", "passed"]
    assert report["linux_visible_ram_bytes"] == 16 * 1024**3
    assert report["max_observed_host_swap_used_bytes"] == 1024**3
    assert report["host_memory_sample_count"] >= 2
    assert report["container_peak_memory_measured"] is False
    assert report["container_oom_measured"] is False
    assert "private-credential" not in json.dumps(report)
    assert set(report) == {
        "schema", "qualification", "checks_result", "first_failure_phase",
        "total_duration_ms", "phases", "linux_visible_logical_cpus",
        "linux_visible_ram_bytes", "initial_free_disk_bytes",
        "host_memory_sample_count", "max_observed_host_used_memory_bytes",
        "max_observed_host_swap_used_bytes", "host_measurement_complete",
        "container_peak_memory_measured", "container_oom_measured",
    }


def test_failed_runner_writes_only_unqualified_redacted_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    install = tmp_path / "install"
    integration = tmp_path / "integration"
    for path in (source, install, integration):
        path.mkdir()
    diagnostic_output = tmp_path / "diagnostic.json"
    output = tmp_path / "success.json"
    args = argparse.Namespace(
        state_root=tmp_path, source_checkout=source, install_root=install,
        integration_checkout=integration, secret_root=tmp_path / "secrets",
        diagnostic_output=diagnostic_output,
        output=output,
    )
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", lambda *_args: args)
    monkeypatch.setattr(runner, "run", lambda *_args: (_ for _ in ()).throw(
        ValueError("private-credential")))
    assert runner.main() == 2
    report = json.loads(diagnostic_output.read_text(encoding="utf-8"))
    assert report["checks_result"] == "failed"
    assert report["qualification"] == "unqualified"
    assert report["first_failure_phase"] == "input_validation"
    assert "private-credential" not in json.dumps(report)
    assert not output.exists()


def test_success_keeps_installed_result_separate_from_unqualified_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    install = tmp_path / "install"
    integration = tmp_path / "integration"
    secrets = tmp_path / "secrets"
    for path in (source, install, integration, secrets):
        path.mkdir()
    args = argparse.Namespace(
        state_root=tmp_path, source_checkout=source, install_root=install,
        integration_checkout=integration, secret_root=secrets,
        diagnostic_output=tmp_path / "diagnostic.json",
        output=tmp_path / "success.json",
    )
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", lambda *_args: args)
    monkeypatch.setattr(runner, "run", lambda *_args: {
        "schema": "marty.selfhost-installed-business-journey/v1",
        "qualification": "unqualified", "public_journey": "passed",
    })
    assert runner.main() == 0
    result = json.loads(args.output.read_text(encoding="utf-8"))
    diagnostics = json.loads(args.diagnostic_output.read_text(encoding="utf-8"))
    assert result["public_journey"] == "passed"
    assert "host_memory_sample_count" not in result
    assert diagnostics["checks_result"] == "passed"
    assert diagnostics["first_failure_phase"] is None
    assert diagnostics["qualification"] == "unqualified"


def test_success_report_write_failure_does_not_claim_runner_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    install = tmp_path / "install"
    integration = tmp_path / "integration"
    secrets = tmp_path / "secrets"
    for path in (source, install, integration, secrets):
        path.mkdir()
    args = argparse.Namespace(
        state_root=tmp_path, source_checkout=source, install_root=install,
        integration_checkout=integration, secret_root=secrets,
        diagnostic_output=tmp_path / "diagnostic.json",
        output=tmp_path / "success.json",
    )
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", lambda *_args: args)
    monkeypatch.setattr(runner, "run", lambda *_args: {"public_journey": "passed"})
    original_open = Path.open

    def fail_success_output(path: Path, *open_args: object, **open_kwargs: object):
        if path == args.output:
            raise PermissionError("cannot write success report")
        return original_open(path, *open_args, **open_kwargs)

    monkeypatch.setattr(Path, "open", fail_success_output)
    assert runner.main() == 2
    diagnostic = json.loads(args.diagnostic_output.read_text(encoding="utf-8"))
    assert diagnostic["checks_result"] == "passed"
    assert diagnostic["qualification"] == "unqualified"
    assert "output_write" not in json.dumps(diagnostic)
    assert not args.output.exists()


def test_existing_diagnostic_file_refuses_to_run_or_write_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    install = tmp_path / "install"
    integration = tmp_path / "integration"
    secrets = tmp_path / "secrets"
    for path in (source, install, integration, secrets):
        path.mkdir()
    diagnostic_output = tmp_path / "diagnostic.json"
    diagnostic_output.write_text("keep", encoding="utf-8")
    args = argparse.Namespace(
        state_root=tmp_path, source_checkout=source, install_root=install,
        integration_checkout=integration, secret_root=secrets,
        diagnostic_output=diagnostic_output, output=tmp_path / "success.json",
    )
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", lambda *_args: args)
    monkeypatch.setattr(runner, "run", lambda *_args: pytest.fail("journey was run"))
    assert runner.main() == 2
    assert diagnostic_output.read_text(encoding="utf-8") == "keep"
    assert not args.output.exists()
