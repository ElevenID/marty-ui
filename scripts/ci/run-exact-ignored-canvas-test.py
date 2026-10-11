"""Run one named ignored Canvas diagnostic and reject vacuous libtest success."""

import re
import subprocess
import sys


SUCCESS = re.compile(
    r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
    r"\d+ filtered out; finished in .+$"
)


def run_exact_ignored(executable: str, test_name: str) -> int:
    try:
        listed = subprocess.run(
            [executable, test_name, "--exact", "--list"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        print(f"Canvas diagnostic listing failed: {error}", file=sys.stderr)
        return 1
    test_lines = [line for line in listed.stdout.splitlines() if line.endswith(": test")]
    if listed.returncode != 0 or test_lines != [f"{test_name}: test"]:
        print(f"Expected exactly one Canvas diagnostic named {test_name}", file=sys.stderr)
        return 1

    try:
        process = subprocess.Popen(
            [executable, test_name, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as error:
        print(f"Canvas diagnostic execution failed: {error}", file=sys.stderr)
        return 1
    summaries = []
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        if line.startswith("test result:"):
            summaries.append(line.strip())
    if process.wait() != 0 or len(summaries) != 1 or not SUCCESS.fullmatch(summaries[0]):
        print(f"Canvas diagnostic {test_name} did not execute exactly once", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: run-exact-ignored-canvas-test.py EXECUTABLE TEST_NAME")
    raise SystemExit(run_exact_ignored(sys.argv[1], sys.argv[2]))
