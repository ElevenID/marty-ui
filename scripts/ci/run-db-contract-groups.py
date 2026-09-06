"""Overlap two database owners, preserving serial execution within each suite."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import tempfile


def run_groups(commands: dict[str, list[str]], directory: Path) -> dict[str, int]:
    def run(name: str, command: list[str]) -> int:
        with (directory / f"{name}.log").open("w", encoding="utf-8") as log:
            try:
                return subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
            except OSError as error:
                log.write(f"Unable to start contract group: {error}\n")
                return 1

    # Wait for every suite even if another fails, so its assertions and cleanup
    # finish. Separate logs avoid interleaving diagnostics from independent DBs.
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {name: executor.submit(run, name, cmd) for name, cmd in commands.items()}
        return {name: future.result() for name, future in futures.items()}


def main() -> int:
    scripts = Path(__file__).resolve().parent
    commands = {
        "published-canvas": ["bash", str(scripts / "run-published-canvas-contracts.sh")],
        "rust-db": ["bash", str(scripts / "run-rust-db-contracts.sh")],
    }
    with tempfile.TemporaryDirectory(prefix="marty-db-groups-") as temporary:
        directory = Path(temporary)
        results = run_groups(commands, directory)
        for name, status in results.items():
            print(f"===== {name}: exit {status} =====", flush=True)
            print((directory / f"{name}.log").read_text(encoding="utf-8"), flush=True)
        return int(any(status != 0 for status in results.values()))


if __name__ == "__main__":
    raise SystemExit(main())
