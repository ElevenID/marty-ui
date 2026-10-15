"""Redacted, best-effort host measurements for a disposable install rehearsal.

Only numeric host resource counters and fixed phase names enter this report.
Container-level memory and OOM evidence must be collected separately before
using a run to establish a supported hardware envelope.
"""

from __future__ import annotations

import os
import shutil
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


PHASES = frozenset({
    "input_validation", "compose_render", "artifact_preflight",
    "public_key_tool_build", "fresh_project", "image_pull", "startup",
    "readiness", "fixture_setup", "custody_verification", "public_journey",
    "cleanup",
})


def linux_memory() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        name, _, raw = line.partition(":")
        if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            fields = raw.split()
            if len(fields) != 2 or fields[1] != "kB":
                raise ValueError("Linux memory counters have an unexpected unit")
            values[name] = int(fields[0]) * 1024
    if set(values) != {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
        raise ValueError("Linux memory counters are incomplete")
    return values


class RunDiagnostics:
    """Record fixed-name timings and sampled Linux-visible memory, not secrets."""

    def __init__(self, state_root: Path, *, interval_seconds: float = 0.5) -> None:
        self.state_root = state_root
        self.interval_seconds = interval_seconds
        self.phases: list[dict[str, int | str]] = []
        self.current_phase = "input_validation"
        self._first_failure_phase: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples = 0
        self._peak_used = 0
        self._peak_swap = 0
        self._sample_error = False
        self._started_ns = time.monotonic_ns()
        self._initial_memory: dict[str, int] | None = None
        self._disk_free_bytes: int | None = None

    def start(self) -> None:
        # A missing counter must not silently become a claim about RAM.
        try:
            self._initial_memory = linux_memory()
            self._disk_free_bytes = shutil.disk_usage(self.state_root).free
        except (OSError, ValueError):
            self._sample_error = True
        self._sample()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _sample(self) -> None:
        try:
            values = linux_memory()
        except (OSError, ValueError):
            self._sample_error = True
            return
        self._samples += 1
        self._peak_used = max(self._peak_used,
                              values["MemTotal"] - values["MemAvailable"])
        self._peak_swap = max(self._peak_swap,
                              values["SwapTotal"] - values["SwapFree"])

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._sample()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                self._sample_error = True
        self._sample()

    @contextmanager
    def measure(self, name: str) -> Iterator[None]:
        if name not in PHASES:
            raise ValueError("unknown installed-journey diagnostic phase")
        self.current_phase = name
        started = time.monotonic_ns()
        status = "passed"
        try:
            yield
        except Exception:
            status = "failed"
            if self._first_failure_phase is None:
                self._first_failure_phase = name
            raise
        finally:
            self.phases.append({"name": name, "status": status,
                                "duration_ms": max(0, (time.monotonic_ns() - started)
                                                   // 1_000_000)})

    def report(self, *, checks_result: str) -> dict:
        if checks_result not in {"passed", "failed"}:
            raise ValueError("unknown diagnostic result")
        memory = self._initial_memory
        return {
            "schema": "marty.selfhost-install-diagnostics/v1",
            "qualification": "unqualified",
            "checks_result": checks_result,
            "first_failure_phase": (
                self._first_failure_phase or self.current_phase
                if checks_result == "failed" else None
            ),
            "total_duration_ms": max(0, (time.monotonic_ns() - self._started_ns)
                                       // 1_000_000),
            "phases": self.phases,
            "linux_visible_logical_cpus": os.cpu_count(),
            "linux_visible_ram_bytes": memory["MemTotal"] if memory else None,
            "initial_free_disk_bytes": self._disk_free_bytes,
            "host_memory_sample_count": self._samples,
            "max_observed_host_used_memory_bytes": self._peak_used or None,
            "max_observed_host_swap_used_bytes": self._peak_swap if self._samples else None,
            "host_measurement_complete": bool(self._samples and not self._sample_error),
            "container_peak_memory_measured": False,
            "container_oom_measured": False,
        }
