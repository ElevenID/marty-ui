"""Overlap independent database owners, preserving serial execution within each suite."""

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from time import monotonic


HEARTBEAT_SECONDS = 30
PREFLIGHT_MODES = (
    "mixed-roster-preflight",
    "body-timeout-preflight",
    "timeout-preflight",
    "lease-expiry-preflight",
)
EVIDENCE_NAME = "canvas-published-preflights.sha256"
RUN_IDENTITY = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")


def _run_identity() -> tuple[str, ...] | None:
    identity = tuple(os.environ.get(name, "") for name in RUN_IDENTITY)
    return identity if all(identity) else None


def _preflight_evidence() -> Path | None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    return (
        Path(runner_temp) / EVIDENCE_NAME if runner_temp and _run_identity() else None
    )


def _canvas_executable() -> Path:
    runner_temp = os.environ["RUNNER_TEMP"]
    artifacts = Path(runner_temp) / "rust-test-artifacts.json"
    with artifacts.open(encoding="utf-8") as source:
        executables = {
            artifact["executable"]
            for line in source
            if (artifact := json.loads(line)).get("reason") == "compiler-artifact"
            and "#marty-service-acceptance@" in artifact.get("package_id", "")
            and artifact.get("target", {}).get("name")
            == "canvas_published_worker_contract"
            and artifact.get("executable") is not None
        }
    if len(executables) != 1:
        raise ValueError("Expected exactly one Canvas worker contract executable")
    executable = Path(executables.pop())
    if not executable.is_file():
        raise ValueError("Canvas contract executable is missing")
    return executable


def _executable_digest() -> str:
    digest = hashlib.sha256()
    with _canvas_executable().open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_preflight_evidence() -> bool:
    evidence = _preflight_evidence()
    if evidence is None or not evidence.is_file():
        return False
    try:
        expected = "\n".join((_executable_digest(), *_run_identity())) + "\n"
        return evidence.read_text(encoding="ascii") == expected
    except (OSError, ValueError, KeyError):
        return False


def _record_preflight_evidence() -> None:
    evidence = _preflight_evidence()
    if evidence is None:
        return  # Local preflight runs retain full coverage in the later suite.
    digest = _executable_digest()
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", newline="\n", dir=evidence.parent, delete=False
    ) as temporary:
        temporary.write("\n".join((digest, *_run_identity())) + "\n")
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, evidence)


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
    if mode in ("database", "canvas"):
        published_mode = ["full-after-preflights"] if _has_preflight_evidence() else []
        commands: dict[str, list[str]] = {
            "published-canvas": [
                "bash",
                str(scripts / "run-published-canvas-contracts.sh"),
                *published_mode,
            ],
        }
        if mode == "database":
            commands["rust-db"] = ["bash", str(scripts / "run-rust-db-contracts.sh")]
    elif mode == "rust-db":
        commands = {"rust-db": ["bash", str(scripts / "run-rust-db-contracts.sh")]}
    elif mode == "preflights":
        evidence = _preflight_evidence()
        if evidence is not None:
            evidence.unlink(missing_ok=True)  # A failed rerun cannot reuse old proof.
        # Longest first keeps the two workers busy. Each exact preflight owns
        # its disposable Docker database and dynamically allocated HTTPS ports.
        commands = {
            name: ["bash", str(scripts / "run-published-canvas-contracts.sh"), name]
            for name in PREFLIGHT_MODES
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
        failed = any(status != 0 for status in results.values())
        if mode == "preflights" and set(results) != set(PREFLIGHT_MODES):
            failed = True
        if mode == "preflights" and not failed:
            try:
                _record_preflight_evidence()
            except (OSError, ValueError, KeyError) as error:
                print(
                    f"[db-contracts] unable to record preflight evidence: {error}",
                    file=sys.stderr,
                )
                return 1
        return int(failed)


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["preflights"], ["canvas"], ["rust-db"]):
        raise SystemExit("Usage: run-db-contract-groups.py [preflights|canvas|rust-db]")
    raise SystemExit(main(sys.argv[1] if sys.argv[1:] else "database"))
