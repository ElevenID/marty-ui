"""Observe three exact pinned Python URL helpers; no provider or runtime imports.

This reference-only tool prints an artifact or checks it. It never writes the
frozen artifact, changes production configuration, or contacts a service.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

# -I deliberately excludes ambient PYTHONPATH and the caller's working directory.
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
pinned = importlib.import_module("capture_canvas_mirror_reference")
owned_log_streams = importlib.import_module(
    "canvas_worker_output_capture"
).owned_log_streams

ROOT = SCRIPTS.parent
SCENARIOS = ROOT / "contracts/canvas-url-template-scenarios.json"
REFERENCE = ROOT / "contracts/canvas-url-template-python-reference.json"
SCHEMA = "marty.canvas-url-template-reference/v1"
HELPERS = {
    "assertion": ("_badgr_assertion_url", "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE"),
    "validation": ("_badgr_validation_url", "CANVAS_CREDENTIALS_VALIDATE_URL_TEMPLATE"),
    "revoke": ("_badgr_revoke_url", "CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE"),
}
CAP = 4 * 1024 * 1024
EXPECTED_DEFINITIONS = {
    "issuance.domain.entities": [
        "Any",
        "CredentialDeliveryRecord",
        "CredentialDeliveryStatus",
        "DeliveryTarget",
        "Enum",
        "dataclass",
        "datetime",
        "field",
        "timezone",
        "uuid",
    ],
    pinned.ADAPTER: [
        "CredentialDeliveryRecord",
        "_badgr_assertion_url",
        "_badgr_revoke_url",
        "_badgr_validation_url",
        "os",
        "quote",
    ],
}


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate reference JSON key")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("Nonfinite reference JSON value")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Nonfinite reference JSON value")
        return result

    if len(raw) > CAP:
        raise ValueError("Reference JSON exceeds limit")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float
    )


def scenarios():
    result = strict_json(pinned.canonical_json_bytes(SCENARIOS.read_bytes()))
    if not isinstance(result, dict) or set(result) != {"schema", "cases"}:
        raise ValueError("Invalid scenario envelope")
    if result["schema"] != "marty.canvas-url-template-scenarios/v1":
        raise ValueError("Unexpected scenario schema")
    cases = result["cases"]
    if not isinstance(cases, list) or not cases:
        raise ValueError("Missing template scenarios")
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id",
            "operation",
            "template",
            "arguments",
        }:
            raise ValueError("Invalid template scenario")
        if not isinstance(case["id"], str) or case["id"] in seen:
            raise ValueError("Invalid or duplicate scenario identity")
        seen.add(case["id"])
        if case["operation"] not in HELPERS or not isinstance(case["arguments"], dict):
            raise ValueError("Invalid helper selection")
        if case["template"] is not None and not isinstance(case["template"], str):
            raise ValueError("Invalid template value")
        expected = (
            {"api_base_url", "external_credential_id"}
            if case["operation"] == "revoke"
            else {"api_base_url", "scope", "badgeclass_id", "issuer_id"}
        )
        if set(case["arguments"]) != expected or any(
            v is not None and not isinstance(v, str) for v in case["arguments"].values()
        ):
            raise ValueError("Invalid helper arguments")
    return result


def observe_sources(sources):
    pinned.verify_sources(sources)
    specification = scenarios()
    scenario_hash = hashlib.sha256(
        pinned.canonical_json_bytes(SCENARIOS.read_bytes())
    ).hexdigest()
    # Read all required assets before execution fencing; no dotenv or application
    # module imports. PinnedDefinitions preserves original module future flags.
    loader = pinned.PinnedDefinitions(sources)
    try:
        with patch.dict(os.environ, {}, clear=True):
            adapter = loader.load(pinned.ADAPTER, [v[0] for v in HELPERS.values()])
            loader.validate_bindings()
            if loader.selected != EXPECTED_DEFINITIONS:
                raise ValueError("Pinned URL helper definition closure differs")
            violations = []

            def audit(event, _arguments):
                if event in {
                    "open",
                    "socket.__new__",
                    "socket.getaddrinfo",
                    "subprocess.Popen",
                    "os.system",
                    "os.fork",
                    "os.posix_spawn",
                    "ctypes.dlopen",
                }:
                    violations.append(event)
                    raise RuntimeError(
                        "Template reference infrastructure access denied"
                    )

            # This function runs only in the owned short-lived child. Audit
            # hooks intentionally survive until its exit, never in a test host.
            sys.addaudithook(audit)
            observations = []
            for case in specification["cases"]:
                name, environment = HELPERS[case["operation"]]
                arguments = dict(case["arguments"])
                if case["operation"] == "validation":
                    # Exact pinned helper does not access this argument.
                    arguments["delivery_record"] = None
                setting = (
                    {} if case["template"] is None else {environment: case["template"]}
                )
                with patch.dict(os.environ, setting, clear=True):
                    try:
                        value = getattr(adapter, name)(**arguments)
                        if not isinstance(value, str):
                            raise AssertionError("Unexpected helper return type")
                        outcome = {"url": value}
                    except (
                        KeyError,
                        IndexError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        UnicodeError,
                        OverflowError,
                    ) as error:
                        outcome = {
                            "error": {
                                "type": type(error).__name__,
                                "message": str(error),
                            }
                        }
                if violations:
                    raise AssertionError(
                        "Infrastructure failure cannot become a helper observation"
                    )
                observations.append(
                    {"id": case["id"], "operation": case["operation"], **outcome}
                )
            if violations:
                raise AssertionError("Template reference infrastructure violation")
            return {
                "schema": SCHEMA,
                "source_commit": pinned.REVISION,
                "source_blobs": {
                    name: pinned.SOURCES[name][1] for name in loader.selected
                },
                "selected_definitions": loader.selected,
                "scenario_sha256": scenario_hash,
                "observations": observations,
            }
    finally:
        loader.close()


def validate_result(result):
    specification = scenarios()
    if not isinstance(result, dict) or set(result) != {
        "schema",
        "source_commit",
        "source_blobs",
        "selected_definitions",
        "scenario_sha256",
        "observations",
    }:
        raise ValueError("Invalid terminal template envelope")
    if result["schema"] != SCHEMA or result["source_commit"] != pinned.REVISION:
        raise ValueError("Unexpected template reference provenance")
    expected_hash = hashlib.sha256(
        pinned.canonical_json_bytes(SCENARIOS.read_bytes())
    ).hexdigest()
    if result["scenario_sha256"] != expected_hash:
        raise ValueError("Template scenarios changed")
    rows = result["observations"]
    if not isinstance(rows, list) or len(rows) != len(specification["cases"]):
        raise ValueError("Incomplete template observations")
    for case, row in zip(specification["cases"], rows, strict=True):
        if (
            not isinstance(row, dict)
            or row.get("id") != case["id"]
            or row.get("operation") != case["operation"]
        ):
            raise ValueError("Template observation identity differs")
        if set(row) == {"id", "operation", "url"}:
            if not isinstance(row["url"], str):
                raise ValueError("Invalid observed URL")
        elif set(row) == {"id", "operation", "error"}:
            error = row["error"]
            if (
                not isinstance(error, dict)
                or set(error) != {"type", "message"}
                or not all(isinstance(v, str) for v in error.values())
            ):
                raise ValueError("Invalid helper error observation")
        else:
            raise ValueError("Ambiguous helper outcome")
    selected = result["selected_definitions"]
    if (
        selected != EXPECTED_DEFINITIONS
        or not isinstance(result["source_blobs"], dict)
        or set(result["source_blobs"]) != set(selected)
    ):
        raise ValueError("Missing selected source provenance")
    for name, definitions in selected.items():
        if (
            name not in pinned.SOURCES
            or result["source_blobs"][name] != pinned.SOURCES[name][1]
            or not isinstance(definitions, list)
            or not all(isinstance(v, str) for v in definitions)
        ):
            raise ValueError("Invalid selected source provenance")


def bounded_child(command, source_input, *, timeout=15, cap=CAP):
    """Independent regular-file readers, finite wait/reap, no pipe descendants."""
    if timeout <= 0 or cap <= 0 or len(source_input) > cap:
        raise ValueError("Invalid bounded template child inputs")
    environment = {
        k: os.environ[k]
        for k in ("SystemRoot", "WINDIR", "SystemDrive")
        if k in os.environ
    }
    environment.update(
        PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1"
    )
    with (
        tempfile.TemporaryDirectory(
            prefix="canvas-url-reference-", dir=ROOT
        ) as directory,
        ExitStack() as stack,
    ):
        input_file = stack.enter_context(tempfile.TemporaryFile(dir=directory))
        input_file.write(source_input)
        input_file.seek(0)
        stdout, stdout_reader = owned_log_streams(stack, directory)
        stderr, stderr_reader = owned_log_streams(stack, directory)
        child = subprocess.Popen(
            command,
            stdin=input_file,
            stdout=stdout,
            stderr=stderr,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + timeout
        try:
            while True:
                if any(
                    os.fstat(v.fileno()).st_size > cap
                    for v in (stdout_reader, stderr_reader)
                ):
                    raise RuntimeError("Template observation output exceeded limit")
                if child.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Template observation deadline exceeded")
                time.sleep(0.01)
            output = stdout_reader.read(cap + 1)
            errors = stderr_reader.read(cap + 1)
            if len(output) > cap or len(errors) > cap:
                raise RuntimeError("Template observation output exceeded limit")
            if child.returncode != 0 or errors:
                raise RuntimeError("Template observation child failed")
            result = strict_json(output)
            validate_result(result)
            return result
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("credentials_checkout", type=Path, nargs="?")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("Python 3.12 is required for the pinned reference")
    if args.worker:
        result = observe_sources(strict_json(sys.stdin.buffer.read(CAP + 1)))
    else:
        if args.credentials_checkout is None:
            parser.error("credentials_checkout is required")
        sources = pinned.read_sources(args.credentials_checkout)
        source_input = json.dumps(sources, ensure_ascii=True, allow_nan=False).encode()
        if len(source_input) > CAP:
            raise ValueError("Pinned source envelope exceeds limit")
        result = bounded_child(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
            source_input,
        )
    encoded = (
        json.dumps(result, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2)
        + "\n"
    )
    if args.check:
        if pinned.canonical_json_bytes(REFERENCE.read_bytes()).decode() != encoded:
            raise ValueError("Frozen Canvas URL template observations differ")
        print(
            f"Canvas URL template reference PASS: {len(result['observations'])} helper observations"
        )
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
