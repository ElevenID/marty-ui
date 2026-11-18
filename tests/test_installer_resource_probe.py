"""Bounded diagnostic sampling; these fixtures do not qualify a host."""
import io
import json
import os
from pathlib import Path
import sys
import subprocess

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_resource_probe as probe

BOOT = "11111111-1111-4111-8111-111111111111"
MEMORY = "MemTotal: 4096 kB\nMemAvailable: 2048 kB\nSwapTotal: 1024 kB\nSwapFree: 512 kB\n"


def test_resource_sample_is_sanitized_and_explicitly_unqualified():
    files = {
        "/proc/sys/kernel/random/boot_id": BOOT + "\n",
        "/proc/meminfo": MEMORY,
        "/proc/vmstat": "pgfault 123\noom_kill 2\n",
        "/proc/pressure/memory": "some avg10=0.00 total=25\nfull avg10=0.00 total=10\n",
    }
    result = probe.sample("initial", reader=files.__getitem__,
                          disk=lambda: dict(device=7, free_bytes=123),
                          clock=lambda: 100, monotonic=lambda: 200)
    assert result["memory_bytes"]["MemTotal"] == 4096 * 1024
    assert result["memory_pressure_total_usec"] == dict(some=25, full=10)
    assert result["oom_kill_total"] == 2
    assert result["guest_boot_id"] == BOOT
    assert result["acceptance"] is False and result["installation_ready"] is False
    assert result["not_atomic_snapshot"] is True
    assert len(json.dumps(result).encode()) <= probe.MAX_RECORD_BYTES
    assert "pgfault" not in json.dumps(result)


@pytest.mark.parametrize("raw", [
    MEMORY + "MemTotal: 1 kB\n", MEMORY.replace("4096 kB", "1 kB"),
    MEMORY.replace("512 kB", "2048 kB"), MEMORY.replace("2048 kB", "x kB"),
    MEMORY.replace("MemTotal: 4096 kB\n", ""), MEMORY.replace("4096 kB", "4096 MB"),
])
def test_memory_refuses_ambiguous_or_inconsistent_measurements(raw):
    with pytest.raises(ValueError):
        probe.memory(raw)


@pytest.mark.parametrize("raw", ["", "oom_kill -1\n", "oom_kill 1\noom_kill 2\n"])
def test_oom_requires_one_real_counter(raw):
    with pytest.raises(ValueError):
        probe.oom(raw)


def test_stop_emits_final_sample_without_waiting_for_full_duration():
    output = io.StringIO()
    observed = []

    def observe(phase):
        observed.append(phase)
        return dict(phase=phase, acceptance=False)

    probe.run(duration=1800, interval=5, output=output, control=object(),
              observe=observe, clock=lambda: 0, wait=lambda *_args: True)
    assert observed == ["initial", "final"]
    assert [json.loads(line)["phase"] for line in output.getvalue().splitlines()] == observed


def test_duration_bounds_samples_and_always_finishes():
    current = [0]
    output = io.StringIO()

    def wait(_stream, seconds):
        current[0] += seconds
        return False

    probe.run(duration=12, interval=5, output=output, control=object(),
              observe=lambda phase: dict(phase=phase), clock=lambda: current[0], wait=wait)
    assert [json.loads(line)["phase"] for line in output.getvalue().splitlines()] == [
        "initial", "periodic", "periodic", "final"]
    assert current[0] == 12


@pytest.mark.parametrize("duration,interval", [(1801, 5), (0, 5), (1800, 1), (10, 0)])
def test_invalid_sampling_budget_produces_no_output(duration, interval):
    output = io.StringIO()
    with pytest.raises(ValueError):
        probe.run(duration=duration, interval=interval, output=output, control=object())
    assert output.getvalue() == ""


def test_broken_wait_cannot_produce_unbounded_output():
    output = io.StringIO()
    with pytest.raises(ValueError):
        probe.run(duration=10, interval=5, output=output, control=object(),
                  observe=lambda phase: dict(phase=phase), clock=lambda: 0,
                  wait=lambda *_args: False)
    assert len(output.getvalue().splitlines()) == probe.MAX_RECORDS


def test_fragmented_stop_is_bounded_and_partial_stall_refuses(monkeypatch):
    stream = io.BytesIO()
    monkeypatch.setattr(stream, "fileno", lambda: 123)
    chunks = iter([b"s", b"top\n"])
    monkeypatch.setattr(probe.os, "read", lambda *_args: next(chunks))
    monkeypatch.setattr(probe.select, "select", lambda *_args: ([stream], [], []))
    assert probe.wait_control(stream, 1) is True
    chunks = iter([b"s"])
    readiness = iter([([stream], [], []), ([], [], [])])
    monkeypatch.setattr(probe.select, "select", lambda *_args: next(readiness))
    with pytest.raises(ValueError):
        probe.wait_control(stream, 1)


@pytest.mark.skipif(sys.platform != "linux", reason="real watchdog and pipe require Linux")
def test_standalone_watchdog_exits_when_controller_keeps_full_pipe_open():
    read_fd, write_fd = os.pipe()
    process = None
    try:
        os.set_blocking(write_fd, False)
        while True:
            try:
                os.write(write_fd, b"x" * 4096)
            except BlockingIOError:
                break
        while True:
            try:
                os.write(write_fd, b"x")
            except BlockingIOError:
                break
        os.set_blocking(write_fd, True)
        code = (
            "import sys; sys.path.insert(0, 'scripts'); "
            "import installer_resource_probe as p; original=p.run; "
            "p.run=lambda **kwargs: original(**kwargs, observe=lambda phase: {'phase':phase}); "
            "p.main(['--duration','1','--interval','1'])"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE, stdout=write_fd, stderr=subprocess.DEVNULL,
        )
        # Keep the reader open and deliberately never drain it. The child must
        # exit by its own watchdog rather than a BrokenPipeError or parent kill.
        assert process.wait(timeout=1 + probe.WATCHDOG_GRACE + 4) == 124
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stdin.close()
        os.close(write_fd)
        os.close(read_fd)
