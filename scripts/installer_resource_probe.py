#!/usr/bin/env python3
"""Bounded read-only Linux resource samples for an unqualified installer trial.

Emit JSON lines to the controller. Read no environment, credentials, application
data or process arguments. A stop line or EOF ends sampling with a final sample;
the duration and record limits also bound a disconnected or abandoned probe.
The standalone watchdog allows five seconds beyond the requested duration and
exits 124 without flushing if any I/O remains blocked. Observation errors exit 1.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time
import uuid

SCHEMA = "elevenid.installer-engineering-resource-sample/v1"
MAX_DURATION = 1800
MAX_RECORDS = 362
MAX_RECORD_BYTES = 2048
WATCHDOG_GRACE = 5
DOCKER_ROOT = Path("/var/lib/docker")


def require(value):
    if not value:
        raise ValueError("engineering resource observation unavailable")


def read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536)
    return raw.decode("ascii")


def memory(raw):
    values = {}
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    for line in raw.splitlines():
        name, _, value = line.partition(":")
        if name not in wanted:
            continue
        parts = value.split()
        require(name not in values and len(parts) == 2
                and parts[0].isascii() and parts[0].isdecimal() and parts[1] == "kB")
        values[name] = int(parts[0]) * 1024
    require(set(values) == wanted and values["MemTotal"] > 0
            and values["MemAvailable"] <= values["MemTotal"]
            and values["SwapFree"] <= values["SwapTotal"])
    return values


def oom(raw):
    entries = [line.split() for line in raw.splitlines() if line.startswith("oom_kill ")]
    require(len(entries) == 1 and len(entries[0]) == 2
            and entries[0][1].isascii() and entries[0][1].isdecimal())
    return int(entries[0][1])


def pressure(raw):
    result = {}
    for line in raw.splitlines():
        parts = line.split()
        require(parts and parts[0] in ("some", "full") and parts[0] not in result)
        totals = [part.removeprefix("total=") for part in parts[1:] if part.startswith("total=")]
        require(len(totals) == 1 and totals[0].isascii() and totals[0].isdecimal())
        result[parts[0]] = int(totals[0])
    require(set(result) == {"some", "full"})
    return result


def filesystem():
    require(DOCKER_ROOT.resolve() == DOCKER_ROOT)
    info = DOCKER_ROOT.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0)
    fs = os.statvfs(DOCKER_ROOT)
    return dict(device=info.st_dev, free_bytes=fs.f_bavail * fs.f_frsize)


def sample(phase, *, reader=read, disk=filesystem, clock=time.time,
           monotonic=time.monotonic_ns):
    require(phase in ("initial", "periodic", "final"))
    boot = reader("/proc/sys/kernel/random/boot_id").strip()
    require(str(uuid.UUID(boot)) == boot)
    result = dict(schema=SCHEMA, phase=phase, guest_boot_id=boot,
                  observed_at=int(clock()), monotonic_ns=monotonic(),
                  memory_bytes=memory(reader("/proc/meminfo")),
                  oom_kill_total=oom(reader("/proc/vmstat")),
                  memory_pressure_total_usec=pressure(reader("/proc/pressure/memory")),
                  docker_filesystem=disk(), not_atomic_snapshot=True,
                  acceptance=False, installation_ready=False)
    require(reader("/proc/sys/kernel/random/boot_id").strip() == boot)
    return result


def wait_control(stream, seconds):
    deadline = time.monotonic() + seconds
    received = b""
    while True:
        if not select.select([stream], [], [], max(0, deadline - time.monotonic()))[0]:
            require(not received)
            return False
        chunk = os.read(stream.fileno(), 6 - len(received))
        if not chunk:
            require(not received)
            return True
        received += chunk
        require(b"stop\n".startswith(received))
        if received == b"stop\n":
            return True


def run(*, duration, interval, output, control, observe=sample,
        clock=time.monotonic, wait=wait_control):
    require(type(duration) is int and 1 <= duration <= MAX_DURATION
            and type(interval) is int and 1 <= interval <= 30
            and (duration + interval - 1) // interval <= MAX_RECORDS - 2)
    deadline = clock() + duration
    count = 0

    def emit(phase):
        nonlocal count
        count += 1
        require(count <= MAX_RECORDS)
        raw = json.dumps(observe(phase), sort_keys=True, separators=(",", ":")) + "\n"
        require(len(raw.encode("ascii")) <= MAX_RECORD_BYTES)
        output.write(raw)
        output.flush()

    emit("initial")
    while True:
        remaining = deadline - clock()
        if remaining <= 0 or wait(control, min(interval, remaining)):
            emit("final")
            return
        if clock() < deadline:
            emit("periodic")


@contextmanager
def watchdog(seconds):
    """Bound all standalone I/O, including a blocked controller output pipe."""
    require(sys.platform == "linux" and signal.getitimer(signal.ITIMER_REAL) == (0, 0))
    previous = signal.getsignal(signal.SIGALRM)
    # Avoid any potentially blocking output in this process-wide last resort.
    # Exit 124 deliberately leaves the controller's partial JSONL incomplete.
    signal.signal(signal.SIGALRM, lambda *_args: os._exit(124))
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=MAX_DURATION)
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        require(1 <= args.duration <= MAX_DURATION)
        with watchdog(args.duration + WATCHDOG_GRACE):
            run(duration=args.duration, interval=args.interval,
                output=sys.stdout, control=sys.stdin.buffer)
    except (ValueError, OSError, UnicodeError):
        # A failed output stream may retain buffered bytes. Avoid shutdown
        # flushing or a second potentially blocked stderr stream on failure.
        os._exit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
