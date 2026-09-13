"""Closed source-derived shutdown controls, not a new worker capture result."""

import importlib
import hashlib
from contextlib import ExitStack
import io
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKER = "/app/services/issuance/canvas_worker.py"
ASYNCIO = "/usr/local/lib/python3.12/asyncio/"
EXPECTED_CHAINS = (
    (
        (ASYNCIO + "runners.py", 118, "run"),
        (ASYNCIO + "base_events.py", 691, "run_until_complete"),
        (WORKER, 676, "_main"),
        (WORKER, 649, "run_canvas_sync_worker_loop"),
        (ASYNCIO + "tasks.py", 520, "wait_for"),
        (ASYNCIO + "locks.py", 212, "wait"),
    ),
    (
        ("<frozen runpy>", 198, "_run_module_as_main"),
        ("<frozen runpy>", 88, "_run_code"),
        (WORKER, 683, "<module>"),
        (ASYNCIO + "runners.py", 195, "run"),
        (ASYNCIO + "runners.py", 123, "run"),
    ),
)
WARNINGS = (
    "WARNING:issuance.infrastructure.api.routes:REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail\n"
    "WARNING:issuance.infrastructure.api.routes:CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail\n"
).encode()


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("canvas_worker_shutdown_output"),
        importlib.import_module("run_canvas_worker_body_timeout_oracle"),
    )


@pytest.fixture
def sources():
    # Synthetic verified-source boundary for parser tests, not fabricated image
    # evidence. The real source-hash reader is exercised separately below.
    return {
        (path, number): f"synthetic_verified_source_{number}()"
        for chain in EXPECTED_CHAINS
        for path, number, _ in chain
        if path != "<frozen runpy>"
    }


def frame_lines(frame, sources, *, carets=False):
    path, line, function = frame
    result = [f'  File "{path}", line {line}, in {function}']
    if not path.startswith("<frozen"):
        result.append("    " + sources[path, line])
        if carets:
            result.append("    ~~~~^^^^")
    return result


def render_trace(sources, *, carets=False):
    result = ["Traceback (most recent call last):"]
    for frame in EXPECTED_CHAINS[0]:
        result.extend(frame_lines(frame, sources, carets=carets))
    result.extend(
        [
            "asyncio.exceptions.CancelledError",
            "",
            "During handling of the above exception, another exception occurred:",
            "",
            "Traceback (most recent call last):",
        ]
    )
    for frame in EXPECTED_CHAINS[1]:
        result.extend(frame_lines(frame, sources, carets=carets))
    result.append("KeyboardInterrupt")
    return ("\n".join(result) + "\n").encode()


def assert_private_failure(action):
    with pytest.raises(AssertionError) as caught:
        action()
    diagnostic = str(caught.value) + "\n".join(getattr(caught.value, "__notes__", []))
    assert "private-sentinel" not in diagnostic
    return caught.value


@pytest.mark.parametrize("carets", [False, True])
def test_exact_source_derived_frame_sequence_has_a_closed_count_projection(
    modules, sources, carets
):
    profile, _ = modules
    assert profile.FRAME_CHAINS == EXPECTED_CHAINS
    assert profile.PYTHON_VERSION == "3.12.13"
    trace = render_trace(sources, carets=carets)
    assert profile.classify_shutdown_trace(trace, sources) == {
        "exception_chain": ["asyncio.exceptions.CancelledError", "KeyboardInterrupt"],
        "traceback_count": 2,
        "frame_count": 11,
        "trace_line_count": len(trace.splitlines()),
        "caret_line_count": 9 if carets else 0,
        "unexpected_output_empty": True,
    }


@pytest.mark.parametrize(
    "frame",
    [frame for chain in EXPECTED_CHAINS for frame in chain],
    ids=[f"frame-{index}" for index in range(11)],
)
@pytest.mark.parametrize("field", ["path", "line", "function"])
def test_each_frame_must_match_exact_path_line_and_function(
    modules, sources, frame, field
):
    original = frame_lines(frame, sources)[0].encode()
    changed = list(frame)
    changed[{"path": 0, "line": 1, "function": 2}[field]] = (
        999 if field == "line" else "private-sentinel"
    )
    altered = f'  File "{changed[0]}", line {changed[1]}, in {changed[2]}'.encode()
    trace = render_trace(sources).replace(original, altered, 1)
    assert_private_failure(lambda: modules[0].classify_shutdown_trace(trace, sources))


@pytest.mark.parametrize(
    "frame",
    [
        frame
        for chain in EXPECTED_CHAINS
        for frame in chain
        if not frame[0].startswith("<")
    ],
    ids=[f"source-{index}" for index in range(9)],
)
def test_each_displayed_code_line_must_match_verified_source(modules, sources, frame):
    code = ("    " + sources[frame[0], frame[1]]).encode()
    trace = render_trace(sources).replace(code, b"    private-sentinel()", 1)
    assert_private_failure(lambda: modules[0].classify_shutdown_trace(trace, sources))


@pytest.mark.parametrize(
    "mutation",
    [
        "cancel_message",
        "interrupt_message",
        "bridge",
        "extra_frame",
        "extra_event",
        "extra_trace",
        "note",
        "truncated_exception",
        "no_final_newline",
        "crlf",
        "invalid_utf8",
        "oversized",
        "empty",
        "wrong_type",
    ],
)
def test_exception_messages_extra_events_truncation_and_invalid_framing_are_rejected(
    modules, sources, mutation
):
    trace = render_trace(sources)
    if mutation == "cancel_message":
        trace = trace.replace(
            b"asyncio.exceptions.CancelledError\n",
            b"asyncio.exceptions.CancelledError: private-sentinel\n",
        )
    elif mutation == "interrupt_message":
        trace = trace.replace(
            b"KeyboardInterrupt\n", b"KeyboardInterrupt: private-sentinel\n"
        )
    elif mutation == "bridge":
        trace = trace.replace(
            b"During handling of the above exception, another exception occurred:",
            b"The above exception was the direct cause of the following exception:",
        )
    elif mutation == "extra_frame":
        trace = trace.replace(
            b"KeyboardInterrupt\n",
            b'  File "private-sentinel", line 1, in secret\nKeyboardInterrupt\n',
        )
    elif mutation == "extra_event":
        trace += b"WARNING:private-sentinel:unexpected\n"
    elif mutation == "extra_trace":
        trace += trace
    elif mutation == "note":
        trace += b"private-sentinel exception note\n"
    elif mutation == "truncated_exception":
        trace = trace.removesuffix(b"KeyboardInterrupt\n")
    elif mutation == "no_final_newline":
        trace = trace[:-1]
    elif mutation == "crlf":
        trace = trace.replace(b"\n", b"\r\n")
    elif mutation == "invalid_utf8":
        trace += b"\xff\n"
    elif mutation == "oversized":
        trace += b"x" * 65537
    elif mutation == "empty":
        trace = b""
    else:
        trace = trace.decode()
    assert_private_failure(lambda: modules[0].classify_shutdown_trace(trace, sources))


@pytest.mark.parametrize(
    "caret",
    [
        "    private-sentinel",
        "    ^\t",
        "    ^\x1b[31m",
        "    ^é",
        "    ^" * 80,
        "    ^\n    ^",
        "    ",
    ],
)
def test_caret_rendering_cannot_hide_text_ansi_tabs_extra_lines_or_excess_span(
    modules, sources, caret
):
    trace = render_trace(sources, carets=True).replace(
        b"    ~~~~^^^^", caret.encode(), 1
    )
    assert_private_failure(lambda: modules[0].classify_shutdown_trace(trace, sources))


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "quiet",
        "missing_warning",
        "duplicate_warning",
        "unknown_prefix",
        "stdout",
        "token",
        "key",
        "oversize",
    ],
)
def test_post_interrupt_profile_requires_exact_prefix_and_chain_without_secret_output(
    modules, sources, monkeypatch, mutation
):
    profile, _ = modules
    monkeypatch.setattr(profile, "shutdown_source_lines", lambda: sources)
    stdout, stderr = b"", WARNINGS + render_trace(sources)
    if mutation == "quiet":
        stderr = WARNINGS
    elif mutation == "missing_warning":
        stderr = stderr.split(b"\n", 1)[1]
    elif mutation == "duplicate_warning":
        stderr = WARNINGS + stderr
    elif mutation == "unknown_prefix":
        stderr = b"private-sentinel\n" + stderr
    elif mutation == "stdout":
        stdout = b"private-sentinel\n"
    elif mutation == "token":
        stderr += b"private-sentinel-token\n"
    elif mutation == "key":
        stderr += b"synthetic-startup-api-key\n"
    elif mutation == "oversize":
        stderr += b"x" * 65537

    def action():
        return profile.observed_shutdown_profile(
            io.BytesIO(stdout), io.BytesIO(stderr), "private-sentinel-token"
        )

    if mutation is None:
        observed = action()
        assert observed["shutdown"]["frame_count"] == 11
        assert observed["pre_interrupt_profile"]["stdout_empty"] is True
        assert observed["shutdown_source_sha256"] == profile.SOURCE_SHA256
    else:
        assert_private_failure(action)


def test_shutdown_trace_is_still_rejected_by_unchanged_pre_interrupt_profile(
    modules, sources
):
    profile, _ = modules
    assert_private_failure(
        lambda: profile.observed_log_profile(
            io.BytesIO(),
            io.BytesIO(WARNINGS + render_trace(sources)),
            "private-sentinel-token",
        )
    )


@pytest.mark.parametrize(
    "secret",
    [
        b"private-sentinel-token",
        b"synthetic-startup-api-key",
        b"synthetic-startup-hmac-key",
        b"synthetic-local-only",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ],
    ids=["token", "api-key", "hmac-key", "database", "master-key"],
)
@pytest.mark.parametrize("location", ["stdout", "prefix", "trace"])
def test_all_secret_tripwires_are_checked_in_both_streams_before_classification(
    modules, sources, monkeypatch, secret, location
):
    profile, _ = modules
    monkeypatch.setattr(profile, "shutdown_source_lines", lambda: sources)
    out = secret if location == "stdout" else b""
    err = WARNINGS + render_trace(sources)
    if location == "prefix":
        err = secret + b"\n" + err
    elif location == "trace":
        err += secret + b"\n"
    error = assert_private_failure(
        lambda: profile.observed_shutdown_profile(
            io.BytesIO(out), io.BytesIO(err), "private-sentinel-token"
        )
    )
    assert secret.decode() not in str(error)
    assert "authentication material" in str(error)


@pytest.mark.parametrize(
    "mutation",
    [None, "worker", "stdlib", "runpy", "runtime", "missing", "invalid_utf8"],
)
def test_source_reader_checks_raw_hashes_exact_runtime_and_all_owned_files(
    modules, sources, monkeypatch, mutation
):
    profile, _ = modules
    expected_paths = {
        WORKER,
        ASYNCIO + "runners.py",
        ASYNCIO + "base_events.py",
        ASYNCIO + "tasks.py",
        ASYNCIO + "locks.py",
        "/usr/local/lib/python3.12/runpy.py",
    }
    assert set(profile.SOURCE_SHA256) == expected_paths
    assert (
        profile.SOURCE_SHA256[WORKER]
        == "c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a"
    )
    contents = {}
    for path in profile.SOURCE_SHA256:
        line_numbers = [
            number for source_path, number in sources if source_path == path
        ]
        lines = ["# synthetic nonexecuted source"] * max(line_numbers, default=198)
        for number in line_numbers:
            lines[number - 1] = "    " + sources[path, number]
        contents[path] = ("\n".join(lines) + "\n").encode()
    pins = {path: hashlib.sha256(value).hexdigest() for path, value in contents.items()}
    monkeypatch.setattr(profile, "SOURCE_SHA256", pins)
    monkeypatch.setattr(
        profile,
        "python_version",
        lambda: "3.12.12" if mutation == "runtime" else "3.12.13",
    )
    changed = {
        "worker": WORKER,
        "stdlib": ASYNCIO + "runners.py",
        "runpy": "/usr/local/lib/python3.12/runpy.py",
    }.get(mutation)
    if changed:
        contents[changed] += b"# private-sentinel changed source\n"
    if mutation == "invalid_utf8":
        contents[WORKER] += b"\xff"
        pins[WORKER] = hashlib.sha256(contents[WORKER]).hexdigest()
    reads = []

    def read(path):
        if mutation == "missing":
            raise OSError("private-sentinel source path")
        reads.append(path.as_posix())
        return contents[path.as_posix()]

    monkeypatch.setattr(Path, "read_bytes", read)
    if mutation is None:
        assert profile.shutdown_source_lines() == sources
        assert set(reads) == expected_paths
    else:
        assert_private_failure(profile.shutdown_source_lines)
        if mutation == "runtime":
            assert reads == []


@pytest.mark.parametrize(
    "mutation", [None, "secret", "extra_event", "truncated", "exit", "wait_timeout"]
)
def test_real_owned_output_appended_by_wait_is_classified_only_after_exit(
    modules, sources, monkeypatch, tmp_path, mutation
):
    profile, runner = modules
    monkeypatch.setattr(profile, "shutdown_source_lines", lambda: sources)
    calls = []
    with ExitStack() as owner:
        out_writer, out_reader = runner.owned_log_streams(owner, tmp_path)
        err_writer, err_reader = runner.owned_log_streams(owner, tmp_path)
        err_writer.write(WARNINGS)
        err_writer.flush()
        runner.observed_log_profile(out_reader, err_reader, "private-sentinel-token")

        def signal(value):
            assert value == runner.signal.SIGINT
            calls.append("signal")

        def wait(timeout):
            assert timeout == 10 and calls == ["signal"]
            calls.append("wait")
            if mutation == "wait_timeout":
                raise TimeoutError("Synthetic owned wait budget")
            trace = render_trace(sources)
            if mutation == "secret":
                trace += b"private-sentinel-token\n"
            elif mutation == "extra_event":
                trace += b"ERROR:private-sentinel:late worker event\n"
            elif mutation == "truncated":
                trace = trace[:-1]
            err_writer.write(trace)
            err_writer.flush()
            return 0 if mutation == "exit" else -2

        child = SimpleNamespace(send_signal=signal, wait=wait)
        if mutation is None:
            code, observed = runner.finish_and_verify_output(
                child, out_reader, err_reader, "private-sentinel-token"
            )
            assert code == -2 and observed["shutdown"]["frame_count"] == 11
            err_reader.seek(0)
            assert err_reader.read() == WARNINGS + render_trace(sources)
        elif mutation == "wait_timeout":
            with pytest.raises(TimeoutError):
                runner.finish_and_verify_output(
                    child, out_reader, err_reader, "private-sentinel-token"
                )
        else:
            assert_private_failure(
                lambda: runner.finish_and_verify_output(
                    child, out_reader, err_reader, "private-sentinel-token"
                )
            )
        assert calls == ["signal", "wait"]
    assert all(
        stream.closed for stream in (out_writer, out_reader, err_writer, err_reader)
    )


def test_every_proper_line_prefix_remains_an_incomplete_shutdown_trace(
    modules, sources
):
    trace_lines = render_trace(sources, carets=True).splitlines(keepends=True)
    for end in range(len(trace_lines)):
        prefix = b"".join(trace_lines[:end])
        assert_private_failure(
            lambda: modules[0].classify_shutdown_trace(prefix, sources)
        )


def test_frozen_runpy_frame_cannot_receive_an_unverified_source_or_caret_line(
    modules, sources
):
    header = frame_lines(EXPECTED_CHAINS[1][0], sources)[0].encode() + b"\n"
    for extra in (b"    private-sentinel()\n", b"    ^^^\n"):
        trace = render_trace(sources).replace(header, header + extra, 1)
        assert_private_failure(
            lambda: modules[0].classify_shutdown_trace(trace, sources)
        )


def test_shutdown_reader_rejects_growth_after_size_check_without_unbounded_read(
    modules, sources, monkeypatch
):
    profile, _ = modules
    monkeypatch.setattr(profile, "shutdown_source_lines", lambda: sources)

    class GrowingReader(io.BytesIO):
        def seek(self, offset, whence=0):
            if whence == 2:
                return 0  # Simulate append between independent size check/read.
            return super().seek(offset, whence)

        def read(self, size=-1):
            assert size == 65537
            return super().read(size)

    stderr = GrowingReader(WARNINGS + render_trace(sources) + b"x" * 65537)
    assert_private_failure(
        lambda: profile.observed_shutdown_profile(
            io.BytesIO(), stderr, "private-sentinel-token"
        )
    )
