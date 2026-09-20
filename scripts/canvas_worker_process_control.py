"""Payload-safe marker and output-count checks for owned worker test parents."""

import os


def _family(value):
    if value not in ("deadline", "timeout"):
        raise AssertionError("Unexpected owned worker control family")
    return value


def assert_control(control, known, pending=None, *, family="deadline"):
    title = _family(family).capitalize()
    entries = list(control.iterdir())
    if not all(entry.is_file() and not entry.is_symlink() for entry in entries):
        raise AssertionError(
            f"{title} control directory contains an unexpected entry type"
        )
    observed = {entry.name for entry in entries}
    allowed = known | ({pending} if pending is not None else set())
    if not known <= observed <= allowed:
        raise AssertionError(f"{title} control markers are missing or out of order")
    return pending is not None and pending in observed


def write_marker(control, known, name, *, family="deadline"):
    label = _family(family)
    if name in known:
        raise AssertionError(f"Duplicate {label} parent marker")
    assert_control(control, known, family=label)
    (control / name).touch(exist_ok=False)
    known.add(name)


def output_counts(stdout, stderr, *, family="deadline"):
    label = _family(family)
    # Independent read handles only; never inspect or echo captured payloads.
    sizes = [stream.seek(0, os.SEEK_END) for stream in (stdout, stderr)]
    return f"Owned {label} child output bytes: stdout={sizes[0]}, stderr={sizes[1]}"
