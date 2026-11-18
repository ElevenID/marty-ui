"""Overlap independent database owners, preserving serial execution within each suite."""

import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from threading import Lock
from time import monotonic

HEARTBEAT_SECONDS = 30
TIMING_PREFIX = "MARTY_CI_PHASE_V1 "
TARGET_TIMING_PREFIX = "MARTY_CI_TARGET_PHASE_V1 "
TIMING_STATUSES = {"ok", "failed"}
TIMING_NAMES = {"contract": frozenset(['application_template', 'credential_template', 'credential_template_migration', 'general_contracts', 'internal_application', 'issuance_credential', 'issuance_transaction', 'issuer_profile', 'organization_application', 'organization_migration', 'organization_repository', 'passport', 'presentation_policy', 'proof_nonce_postgres_contract', 'retention', 'signing_document', 'signing_registry', 'trust_profile_migration']), "container_startup": frozenset({"postgres_create"}), "database_readiness": frozenset({"postgres_ready"})}
TIMING_PHASES = frozenset(TIMING_NAMES)

def _timing_path() -> Path | None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        return None
    return Path(runner_temp) / "rust-build-evidence" / "db-contract-timing.jsonl"


def _safe_phase(line: str, group: str) -> dict[str, object] | None:
    if not line.startswith(TIMING_PREFIX) or len(line) > 256:
        return None
    try:
        value = json.loads(line[len(TIMING_PREFIX) :])
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "phase",
        "name",
        "duration_ms",
        "status",
    }:
        return None
    phase, name, duration, status = (
        value[key] for key in ("phase", "name", "duration_ms", "status")
    )
    if (
        not isinstance(phase, str)
        or phase not in TIMING_PHASES
        or not isinstance(name, str)
        or name not in TIMING_NAMES[phase]
        or not 1 <= len(name) <= 96
        or not all(
            character.isascii() and (character.isalnum() or character in "_-.")
            for character in name
        )
        or isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 0 <= duration <= 43_200_000
        or not isinstance(status, str)
        or status not in TIMING_STATUSES
    ):
        return None
    result = {"schema": "marty.ci.db-phase/v1", "group": group, **value}
    return result


def _wait_for_groups(futures: dict[str, Future[int]], started: float) -> dict[str, int]:
    """Observe completion without streaming either owner's raw log or command."""
    pending = set(futures.values())
    results = {}
    while pending:
        completed, pending = wait(
            pending, timeout=HEARTBEAT_SECONDS, return_when=FIRST_COMPLETED
        )
        elapsed = int(monotonic() - started)
        for name, future in futures.items():
            if future in completed:
                results[name] = future.result()
                print(
                    f"[db-contracts] completed group={name} exit={results[name]} "
                    f"elapsed={elapsed}s",
                    flush=True,
                )
        if pending and not completed:
            names = ",".join(
                name for name, future in futures.items() if future in pending
            )
            print(
                f"[db-contracts] waiting groups={names} elapsed={elapsed}s", flush=True
            )
    # Completion order must not change the original final log/result order.
    return {name: results[name] for name in futures}


def run_groups(commands: dict[str, list[str]], directory: Path) -> dict[str, int]:
    timing_path = _timing_path()
    timing_lock = Lock()

    def record(value: dict[str, object]) -> None:
        target = f" target={value['target']}" if "target" in value else ""
        print(
            f"[db-timing] group={value['group']}{target} phase={value['phase']} "
            f"name={value['name']} duration_ms={value['duration_ms']} status={value['status']}",
            flush=True,
        )
        if timing_path is None:
            return
        with timing_lock:
            try:
                timing_path.parent.mkdir(parents=True, exist_ok=True)
                with timing_path.open("a", encoding="ascii", newline="\n") as evidence:
                    evidence.write(
                        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
                    )
            except OSError:
                print("[db-timing] optional timing evidence unavailable", flush=True)
                return

    def run(name: str, command: list[str]) -> int:
        group_started = monotonic()
        with (directory / f"{name}.log").open("wb") as log:
            try:
                with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                ) as process:
                    assert process.stdout is not None
                    for line in process.stdout:
                        log.write(line)
                        if not line.startswith(
                            (
                                TIMING_PREFIX.encode("ascii"),
                                TARGET_TIMING_PREFIX.encode("ascii"),
                            )
                        ):
                            continue
                        try:
                            marker = line.decode("ascii").rstrip("\r\n")
                        except UnicodeDecodeError:
                            continue
                        phase = _safe_phase(marker, name)
                        if phase is not None:
                            record(phase)
                    status = process.wait()
            except OSError as error:
                log.write(f"Unable to start contract group: {error}\n".encode())
                status = 1
        record(
            {
                "schema": "marty.ci.db-phase/v1",
                "group": name,
                "phase": "contract",
                "name": "group_total",
                "duration_ms": round((monotonic() - group_started) * 1000),
                "status": "ok" if status == 0 else "failed",
            }
        )
        return status

    # Wait for every suite even if another fails, so its assertions and cleanup
    # finish. Separate logs avoid interleaving diagnostics from independent DBs.
    started = monotonic()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}
        for name, command in commands.items():
            # Names are the caller's fixed, nonsecret group identifiers. Never
            # report command arguments, environment, paths or log contents here.
            print(f"[db-contracts] starting group={name}", flush=True)
            futures[name] = executor.submit(run, name, command)
        return _wait_for_groups(futures, started)


def main(mode: str = "database") -> int:
    if mode not in ("database", "rust-db"):
        raise ValueError("Unsupported platform contract group mode")
    scripts = Path(__file__).resolve().parent
    commands = {"rust-db": ["bash", str(scripts / "run-rust-db-contracts.sh")]}
    with tempfile.TemporaryDirectory(prefix="marty-db-groups-") as temporary:
        directory = Path(temporary)
        results = run_groups(commands, directory)
        for name, status in results.items():
            print(f"===== {name}: exit {status} =====", flush=True)
            print((directory / f"{name}.log").read_text(encoding="utf-8"), flush=True)
        return int(any(status != 0 for status in results.values()))


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["rust-db"]):
        raise SystemExit("Usage: run-db-contract-groups.py [rust-db]")
    raise SystemExit(main(sys.argv[1] if sys.argv[1:] else "database"))
