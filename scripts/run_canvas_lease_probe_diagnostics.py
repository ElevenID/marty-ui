"""Observe bounded failed-blocker fields without editing the frozen probe.

The preparer, oracle, SQL, worker, timing controls and captured reports remain
unchanged. Successful JSON is byte-identical to the preparer's CLI output.
"""

import json
import sys

from prepare_canvas_published_schema import failure_report, prepare


def owned_blocker_diagnostics(failure):
    owner = sys.modules.get("run_canvas_worker_lease_expiry_oracle")
    assertion = getattr(owner, "assert_blocker", None)
    if type(failure) is not AssertionError or not callable(assertion):
        return None
    code = getattr(assertion, "__code__", None)
    current = failure.__traceback__
    while current is not None:
        if current.tb_frame.f_code is code:
            row = current.tb_frame.f_locals.get("row")
            expected = current.tb_frame.f_locals.get("expected_blocker")
            fields = {"waiting_count", "matching_count", "worker_pid", "blocker_pid"}
            if (
                type(row) is dict
                and set(row) == fields
                and all(
                    type(value) is int and 0 <= value <= 2147483647
                    for value in row.values()
                )
                and type(expected) is int
                and 1 < expected <= 2147483647
                and row["blocker_pid"] == expected
            ):
                return dict(row)
            return None
        current = current.tb_next
    return None


def main():
    try:
        print(json.dumps(prepare(), sort_keys=True))
        return 0
    except BaseException as failure:
        report = failure_report(failure)
        diagnostics = owned_blocker_diagnostics(failure)
        if diagnostics is not None:
            report["owned_blocker_diagnostics"] = diagnostics
        print(json.dumps(report, allow_nan=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
