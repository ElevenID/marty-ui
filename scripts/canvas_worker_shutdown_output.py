"""Closed, source-pinned Python idle-SIGINT output; never a generic log filter.

The published worker at idle awaits Event.wait through asyncio.wait_for. Python
3.12.13 Runner cancels that main task on SIGINT and raises KeyboardInterrupt from
the cancellation handler. Only this exact two-trace shutdown path is recognized.
The existing pre-interrupt two-warning profile remains unchanged and mandatory.
"""

import hashlib
from io import BytesIO
from pathlib import Path
from platform import python_version
import re

from canvas_worker_output_capture import observed_log_profile, read_private_output


PYTHON_VERSION = "3.12.13"
WORKER = "/app/services/issuance/canvas_worker.py"
STDLIB = "/usr/local/lib/python3.12/"
SOURCE_SHA256 = {
    WORKER: "c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a",
    STDLIB
    + "asyncio/runners.py": "739e0ecbb335cfec821a39f9e225583b5911bb6e3894ef93782005f852c54263",
    STDLIB
    + "asyncio/base_events.py": "53b71bbbd79e7fb2251460119afc379ebd71bbc599d9018313cc62ef218ae795",
    STDLIB
    + "asyncio/tasks.py": "6f6aad82d597fea1800004075b9a2481604da0035f1143af1eb267823ec460e3",
    STDLIB
    + "asyncio/locks.py": "5234295a0456e9a6ba2e80446848b602cd9195bca4fca2c711c6e3f41989cd86",
    STDLIB
    + "runpy.py": "81e07da29bb2235111079bb64efea7d291639c5d2cf163e7af187d6a38cef389",
}
FRAME_CHAINS = (
    (
        (STDLIB + "asyncio/runners.py", 118, "run"),
        (STDLIB + "asyncio/base_events.py", 691, "run_until_complete"),
        (WORKER, 676, "_main"),
        (WORKER, 649, "run_canvas_sync_worker_loop"),
        (STDLIB + "asyncio/tasks.py", 520, "wait_for"),
        (STDLIB + "asyncio/locks.py", 212, "wait"),
    ),
    (
        ("<frozen runpy>", 198, "_run_module_as_main"),
        ("<frozen runpy>", 88, "_run_code"),
        (WORKER, 683, "<module>"),
        (STDLIB + "asyncio/runners.py", 195, "run"),
        (STDLIB + "asyncio/runners.py", 123, "run"),
    ),
)
TRACEBACK = "Traceback (most recent call last):"
BRIDGE = "During handling of the above exception, another exception occurred:"
EXCEPTIONS = ("asyncio.exceptions.CancelledError", "KeyboardInterrupt")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def shutdown_source_lines():
    """Read only exact immutable files; no application import or source execution."""
    require(python_version() == PYTHON_VERSION, "Unexpected Python shutdown runtime")
    lines_by_path = {}
    for path, expected in SOURCE_SHA256.items():
        try:
            contents = Path(path).read_bytes()
            require(
                hashlib.sha256(contents).hexdigest() == expected,
                "Unexpected immutable shutdown source",
            )
            lines_by_path[path] = contents.decode("utf-8").splitlines()
        except (OSError, UnicodeError):
            raise AssertionError("Immutable shutdown source unavailable") from None
    return {
        (path, number): lines_by_path[path][number - 1].strip()
        for chain in FRAME_CHAINS
        for path, number, _ in chain
        if path != "<frozen runpy>"
    }


def classify_shutdown_trace(trace, sources):
    """Validate every frame, code line, exception and decoration without outputting it."""
    require(
        type(trace) is bytes and 0 < len(trace) <= 65536,
        "Invalid bounded shutdown trace",
    )
    try:
        decoded = trace.decode("utf-8")
    except UnicodeError:
        raise AssertionError("Invalid shutdown trace encoding") from None
    require(
        decoded.endswith("\n") and "\r" not in decoded,
        "Unexpected shutdown trace framing",
    )
    lines = decoded[:-1].split("\n")
    index = 0
    caret_count = 0

    def take(expected):
        nonlocal index
        require(
            index < len(lines) and lines[index] == expected,
            "Shutdown trace differs from the closed source path",
        )
        index += 1

    for chain_index, chain in enumerate(FRAME_CHAINS):
        take(TRACEBACK)
        for path, number, function in chain:
            take(f'  File "{path}", line {number}, in {function}')
            if path == "<frozen runpy>":
                continue
            require((path, number) in sources, "Missing verified shutdown frame source")
            code = "    " + sources[path, number]
            take(code)
            # PEP 657 carets are optional rendering, not new semantic frames.
            # Permit at most one bounded line containing only ASCII spaces and
            # actual ^/~ markers. No text, tabs, ANSI, blank padding or notes.
            if index < len(lines) and re.fullmatch(
                r" {4}[ ~^]*[~^][ ~^]*", lines[index]
            ):
                require(
                    len(lines[index]) <= min(len(code), 256),
                    "Shutdown caret decoration exceeds its source span",
                )
                index += 1
                caret_count += 1
        take(EXCEPTIONS[chain_index])
        if chain_index == 0:
            take("")
            take(BRIDGE)
            take("")
    require(index == len(lines), "Unexpected output after the closed shutdown trace")
    return {
        "exception_chain": list(EXCEPTIONS),
        "traceback_count": len(FRAME_CHAINS),
        "frame_count": sum(map(len, FRAME_CHAINS)),
        "trace_line_count": len(lines),
        "caret_line_count": caret_count,
        "unexpected_output_empty": True,
    }


def observed_shutdown_profile(stdout, stderr, token):
    """Called only after owned SIGINT and terminal wait; quiet is not an alternative."""
    out, err = read_private_output(stdout, stderr, token)
    marker = (TRACEBACK + "\n").encode("ascii")
    start = err.find(marker)
    require(start >= 0, "Expected source-pinned Python shutdown trace is missing")
    # Reuse the unchanged strict warning classifier for everything preceding
    # the trace, including stdout. Unknown logs cannot be hidden in its prefix.
    prefix = observed_log_profile(BytesIO(out), BytesIO(err[:start]), token)
    shutdown = classify_shutdown_trace(err[start:], shutdown_source_lines())
    return {
        "pre_interrupt_profile": prefix,
        "shutdown": shutdown,
        "python_version": PYTHON_VERSION,
        "shutdown_source_sha256": dict(SOURCE_SHA256),
    }
