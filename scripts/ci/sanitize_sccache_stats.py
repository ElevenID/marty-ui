"""Emit only numeric sccache counters safe for a public CI artifact."""

import json
import re
import sys


FIELDS = {
    "Compile requests": "compile_requests",
    "Compile requests executed": "compile_requests_executed",
    "Cache hits": "cache_hits",
    "Cache hits (Rust)": "cache_hits_rust",
    "Cache misses": "cache_misses",
    "Cache misses (Rust)": "cache_misses_rust",
    "Cache timeouts": "cache_timeouts",
    "Cache read errors": "cache_read_errors",
    "Cache write errors": "cache_write_errors",
    "Non-cacheable compilations": "non_cacheable_compilations",
    "Non-cacheable calls": "non_cacheable_calls",
    "Unsupported compiler calls": "unsupported_compiler_calls",
}


def sanitize(lines: list[str]) -> dict[str, int]:
    counters: dict[str, int] = {}
    for line in lines:
        match = re.fullmatch(r"\s*(.*?)\s{2,}(\d+)\s*", line)
        if match and match.group(1) in FIELDS:
            counters[FIELDS[match.group(1)]] = int(match.group(2))
    return counters


if __name__ == "__main__":
    counters = sanitize(sys.stdin.readlines())
    if not counters:
        raise SystemExit("No allowlisted sccache counters available")
    print(
        json.dumps(
            {
                "schema_version": 1,
                "capture_point": "after_reusable_host_compile",
                "counters": counters,
            },
            sort_keys=True,
        )
    )
