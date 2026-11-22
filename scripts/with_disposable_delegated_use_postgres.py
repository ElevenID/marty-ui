#!/usr/bin/env python3
"""Run one delegated-use qualification command against a new loopback cluster.

Supply independently verified PostgreSQL 15+ native binaries. This wrapper does
not install packages, use Docker, contact an existing database or change host
configuration. The test owns its database names and restricted LOGIN roles; the
enclosing cluster is disposable. Loopback trust is intentional for those roles
and is never suitable for a shared or production PostgreSQL deployment.

The evidence directory must not exist. It is created with mode 0700. Child and
PostgreSQL logs remain there on every outcome. Successful runs remove cluster
data and owned temporary state; failed/interrupted runs retain stopped cluster
data and any private temporary files for diagnosis. Only
processes started by this invocation are stopped. No URLs or inherited secrets
are written to the result manifest or printed by this wrapper.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time


class Interrupted(Exception):
    def __init__(self, number: int):
        self.number = number


def interrupt(number, _frame):
    raise Interrupted(number)


def binaries(directory: Path) -> tuple[dict[str, str], str]:
    directory = directory.expanduser().resolve(strict=True)
    commands = {}
    versions = set()
    for name in ("postgres", "initdb", "psql"):
        path = (directory / name).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError("a required PostgreSQL executable is unavailable")
        version = subprocess.run([str(path), "--version"], capture_output=True,
                                 text=True, check=True, timeout=10).stdout.strip()
        match = re.search(r"\(PostgreSQL\) (\d+)(?:\.[0-9]+)+", version)
        if match is None or int(match[1]) < 15:
            raise RuntimeError("the fixture requires PostgreSQL 15 or newer")
        versions.add(match[0])
        commands[name] = str(path)
    if len(versions) != 1:
        raise RuntimeError("the PostgreSQL executable versions do not match")
    return commands, versions.pop()


def clean_environment() -> dict[str, str]:
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith(("PG", "BAO_", "VAULT_", "MARTY_TEST_", "DELEGATED_USE_"))
        and key not in {"DATABASE_URL", "MARTY_DELEGATED_USE_ENABLED"}
        and not key.endswith("_DATABASE_URL")
    }


def stop_child(child: subprocess.Popen | None) -> None:
    if child is None:
        return
    # Both the command and PostgreSQL start new sessions. Signal only their
    # owned groups and check descendants even after the direct child exits.
    for number, seconds in ((signal.SIGTERM, 15), (signal.SIGKILL, 10)):
        try:
            os.killpg(child.pid, number)
        except ProcessLookupError:
            child.wait(timeout=10)
            return
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            child.poll()  # Reap the command when descendants outlive it.
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                child.wait(timeout=10)
                return
            time.sleep(0.1)
    raise RuntimeError("an owned process group did not stop")


def execute(commands: dict[str, str], version: str, evidence: Path,
            command: list[str], timeout: int) -> int:
    evidence = evidence.expanduser().absolute()
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    evidence = evidence.resolve(strict=True)
    data = evidence / "data"
    temporary = evidence / "temporary"
    temporary.mkdir(mode=0o700)
    environment = clean_environment()
    environment["TMPDIR"] = str(temporary)
    result = {"postgres_version": version, "exit_code": 1,
              "postgres_stopped": False, "data_removed": False,
              "temporary_removed": False}
    postgres = child = None
    previous_handlers = {number: signal.signal(number, interrupt)
                         for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        with (evidence / "postgres.log").open("x", encoding="utf-8") as log:
            subprocess.run([
                commands["initdb"], "-D", str(data), "-U", "postgres",
                "--auth-local=trust", "--auth-host=trust", "--no-locale", "-E", "UTF8",
            ], env=environment, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, check=True, timeout=60)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            postgres = subprocess.Popen([
                commands["postgres"], "-D", str(data), "-h", "127.0.0.1",
                "-p", str(port), "-k", "", "-c", "max_connections=120",
                "-c", "shared_buffers=64MB", "-c", "log_statement=none",
            ], env=environment, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, start_new_session=True)
            query = [commands["psql"], "-X", "-qAt", "--no-password", "-h", "127.0.0.1",
                     "-p", str(port), "-U", "postgres", "-d", "postgres",
                     "-v", "ON_ERROR_STOP=1", "-c"]
            deadline = time.monotonic() + 30
            while True:
                if postgres.poll() is not None:
                    raise RuntimeError("the new PostgreSQL process exited before readiness")
                checked = subprocess.run(query + ["SHOW data_directory"], env=environment,
                                         capture_output=True, text=True, timeout=5)
                if checked.returncode == 0:
                    if checked.stdout.strip() != str(data) or postgres.poll() is not None:
                        raise RuntimeError("loopback listener is not this invocation's cluster")
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("new PostgreSQL readiness timed out")
                time.sleep(0.1)
            for database in ("marty_test", "marty_atomic_test"):
                subprocess.run(query + [f"CREATE DATABASE {database}"], env=environment,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=10)
            environment.update({
                "DELEGATED_AUTHORITY_TEST_DATABASE_URL":
                    f"postgresql://postgres@127.0.0.1:{port}/marty_test",
                "FLOW_POSTGRES_TEST_URL":
                    f"postgresql://postgres@127.0.0.1:{port}/marty_atomic_test",
            })
            print("Disposable loopback PostgreSQL ready; running qualification command.", flush=True)
            with (evidence / "child.log").open("x", encoding="utf-8") as child_log:
                child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                         stdout=child_log, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                result["exit_code"] = child.wait(timeout=timeout)
    except Interrupted as error:
        result["exit_code"] = 128 + error.number
        result["failure"] = "interrupted"
    except subprocess.TimeoutExpired:
        result["exit_code"] = 124
        result["failure"] = "timeout"
    except Exception as error:
        result["failure"] = type(error).__name__
    finally:
        for number in previous_handlers:
            signal.signal(number, signal.SIG_IGN)
        try:
            try:
                stop_child(child)
            except Exception:
                result["exit_code"] = 1
                result["failure"] = "child_cleanup_failed"
            try:
                if postgres is not None:
                    if postgres.poll() is not None:
                        # Even a successful test cannot qualify a provider that
                        # died before its planned stop. Preserve the first failure.
                        result["exit_code"] = result["exit_code"] or 1
                        result.setdefault("failure", "postgres_exited_before_cleanup")
                    else:
                        postgres.send_signal(signal.SIGINT)  # Fast, clean stop of this child only.
                        try:
                            if postgres.wait(timeout=30) != 0:
                                result["exit_code"] = result["exit_code"] or 1
                                result.setdefault("failure", "postgres_stop_failed")
                        except subprocess.TimeoutExpired:
                            result["exit_code"] = result["exit_code"] or 1
                            result.setdefault("failure", "postgres_required_forced_stop")
                    # The postmaster's exit alone does not confirm its owned
                    # process group has drained after a crash or forced stop.
                    stop_child(postgres)
                result["postgres_stopped"] = True
            except Exception:
                result["exit_code"] = result["exit_code"] or 1
                result.setdefault("failure", "postgres_cleanup_failed")
        finally:
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)
            if result["exit_code"] == 0 and result["postgres_stopped"]:
                shutil.rmtree(data)
                shutil.rmtree(temporary)
                result["data_removed"] = True
                result["temporary_removed"] = True
            (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Qualification exit {result['exit_code']}; private evidence: {evidence}", flush=True)
    code = int(result["exit_code"])
    return code if code >= 0 else 128 - code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path,
                        help="new private directory under an existing parent")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not 1 <= args.timeout_seconds <= 3600:
        parser.error("a command and a timeout between 1 and 3600 seconds are required")
    if os.geteuid() == 0:
        parser.error("run as the ordinary development user, never root")
    try:
        commands, version = binaries(args.postgres_bin)
        return execute(commands, version, args.evidence_dir, command, args.timeout_seconds)
    except Exception as error:
        print(f"Disposable PostgreSQL fixture failed ({type(error).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
