"""Overlap independent database owners, preserving serial execution within each suite."""

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
import subprocess
import sys
import tempfile
from time import monotonic


HEARTBEAT_SECONDS = 30


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
    def run(name: str, command: list[str]) -> int:
        with (directory / f"{name}.log").open("w", encoding="utf-8") as log:
            try:
                return subprocess.run(
                    command, stdout=log, stderr=subprocess.STDOUT
                ).returncode
            except OSError as error:
                log.write(f"Unable to start contract group: {error}\n")
                return 1

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
    scripts = Path(__file__).resolve().parent
    if mode == "database":
        commands = {
            "published-canvas": [
                "bash",
                str(scripts / "run-published-canvas-contracts.sh"),
            ],
            "rust-db": ["bash", str(scripts / "run-rust-db-contracts.sh")],
        }
    elif mode == "preflights":
        # Longest first keeps the two workers busy. Each exact preflight owns
        # its disposable Docker database and dynamically allocated HTTPS ports.
        commands = {
            name: ["bash", str(scripts / "run-published-canvas-contracts.sh"), name]
            for name in (
                "mixed-roster-preflight",
                "body-timeout-preflight",
                "timeout-preflight",
                "lease-expiry-preflight",
            )
        }
    else:
        raise ValueError("Unsupported contract group mode")
    prefix = "marty-preflight-groups-" if mode == "preflights" else "marty-db-groups-"
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        directory = Path(temporary)
        results = run_groups(commands, directory)
        for name, status in results.items():
            print(f"===== {name}: exit {status} =====", flush=True)
            print((directory / f"{name}.log").read_text(encoding="utf-8"), flush=True)
        return int(any(status != 0 for status in results.values()))


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["preflights"]):
        raise SystemExit("Usage: run-db-contract-groups.py [preflights]")
    raise SystemExit(main("preflights" if sys.argv[1:] else "database"))
