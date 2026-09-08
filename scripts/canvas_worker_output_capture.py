"""Owned child output with independent readers and exact published log provenance."""

import hashlib
from pathlib import Path
import re
import tempfile


def log_counts(contents):
    """Fixed categories only; never expose a logger name or message from the child."""
    counts = dict.fromkeys(
        (
            "Lines",
            "Info",
            "Warning",
            "Error",
            "Other",
            "Worker",
            "Http",
            "Traceback",
            "MissingRevocationUrl",
            "MissingTemplateUrl",
        ),
        0,
    )
    for line in contents.splitlines():
        counts["Lines"] += 1
        match = re.match(rb"^(DEBUG|INFO|WARNING|ERROR|CRITICAL):([^:]+):", line)
        if match:
            level, logger = match.groups()
            counts[
                {
                    b"INFO": "Info",
                    b"WARNING": "Warning",
                    b"ERROR": "Error",
                    b"CRITICAL": "Error",
                }.get(level, "Other")
            ] += 1
            if logger in (b"__main__", b"issuance.canvas_worker"):
                counts["Worker"] += 1
            elif logger in (b"httpx", b"httpcore"):
                counts["Http"] += 1
        else:
            counts["Other"] += 1
        if line.startswith(b"Traceback (most recent call last):"):
            counts["Traceback"] += 1
        for category, message in (
            (
                "MissingRevocationUrl",
                "REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail",
            ),
            (
                "MissingTemplateUrl",
                "CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail",
            ),
        ):
            if line == f"WARNING:issuance.infrastructure.api.routes:{message}".encode():
                counts[category] += 1
    return counts


def observed_log_profile(stdout, stderr, token):
    # Observe actual child output at WARNING level, before the separate SIGINT
    # shutdown boundary. Never retain raw unexpected logs or exception payloads.
    observations = []
    forbidden = (
        token.encode(),
        b"synthetic-startup-api-key",
        b"synthetic-startup-hmac-key",
        b"synthetic-local-only",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    for stream in (stdout, stderr):
        stream.flush()
        assert stream.seek(0, 2) <= 65536, "Unexpectedly large owned worker output"
        stream.seek(0)
        # The child may append after the size check. Bound the read itself too.
        contents = stream.read(65537)
        assert len(contents) <= 65536, "Unexpectedly large owned worker output"
        assert all(value not in contents for value in forbidden), (
            "Synthetic authentication material appeared in worker output"
        )
        observations.append(log_counts(contents))
    expected_stdout = dict.fromkeys(observations[0], 0)
    expected_stderr = {
        **expected_stdout,
        "Lines": 2,
        "Warning": 2,
        "MissingRevocationUrl": 1,
        "MissingTemplateUrl": 1,
    }
    if observations != [expected_stdout, expected_stderr]:
        # Only the two reviewed exact source templates are accepted. Unknown
        # output remains a payload-free failure, including extra known warnings.
        suffix = "".join(
            stream + "".join(f"{key}{value}" for key, value in counts.items())
            for stream, counts in zip(("Stdout", "Stderr"), observations, strict=True)
        )
        raise type(f"DeadlineLogCounts{suffix}", (AssertionError,), {})
    return {
        "stdout_empty": True,
        "stderr_warning_categories": {
            "missing_revocation_profile_service_url": 1,
            "missing_credential_template_service_url": 1,
        },
        "other_output_empty": True,
    }


def owned_log_streams(owner, directory):
    # Child and observer must not share an open-file description: observer seeks
    # must never move the child's write offset. The surrounding owned temporary
    # directory removes the file after ExitStack closes both independent handles.
    writer = owner.enter_context(
        tempfile.NamedTemporaryFile(mode="a+b", dir=directory, delete=False)
    )
    reader = owner.enter_context(open(writer.name, "rb"))
    return writer, reader


def published_log_source_sha256():
    return hashlib.sha256(
        Path("/app/services/issuance/infrastructure/api/routes.py").read_bytes()
    ).hexdigest()
