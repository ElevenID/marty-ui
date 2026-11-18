"""Require the declared public-protocol Rust vector owners in a completed test log."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.check_gateway_public_protocol_contract import (
    VECTOR_TEST_OWNERS,
    _assert_rust_behavior_vector_test_owners,
)


def assert_public_vector_tests_executed(workspace_log: str) -> None:
    """Check exact successful libtest lines without starting a second Cargo run."""
    completed = set(workspace_log.splitlines())
    missing = [
        vector
        for vector, owner in sorted(VECTOR_TEST_OWNERS.items())
        if (
            f"test {Path(owner.source).stem}::tests::{owner.test} ... ok"
            not in completed
        )
    ]
    if missing:
        raise AssertionError(
            "public vector Rust tests did not execute successfully: "
            + ", ".join(missing)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace_log", type=Path)
    args = parser.parse_args()
    _assert_rust_behavior_vector_test_owners()
    assert_public_vector_tests_executed(args.workspace_log.read_text(encoding="utf-8"))
    print(f"Verified {len(VECTOR_TEST_OWNERS)} public vector Rust test executions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
