"""Require retained platform lifecycle cases to run in the workspace log."""
from collections import defaultdict
from pathlib import Path
import re
import sys

from rust_db_obligations import LIBRARY_UNIT_REQUIRED_CASES


def validate(text):
    outcomes = defaultdict(list)
    for name, outcome in re.findall(r"(?m)^test ([A-Za-z0-9_:]+) \.\.\. (.*)$", text):
        outcomes[name].append(outcome)
    for name in LIBRARY_UNIT_REQUIRED_CASES:
        if outcomes[name] != ["ok"]:
            raise ValueError("Required platform lifecycle test did not execute exactly once successfully")



if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected one workspace test log")
    try:
        validate(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit("Platform lifecycle execution proof failed") from error
    print("Platform lifecycle execution: all required cases passed")
