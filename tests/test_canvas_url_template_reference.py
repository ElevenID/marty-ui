"""Frozen helper evidence plus bounded-runner negative controls, stdlib only."""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture_canvas_url_template_reference.py"
spec = importlib.util.spec_from_file_location("url_template_reference", SCRIPT)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def reference():
    return capture.strict_json(capture.REFERENCE.read_bytes())


def test_frozen_artifacts_pin_complete_cases_and_original_source_closure():
    for path, digest in [
        (
            capture.REFERENCE,
            "1824310cfaaa929cb0c902ac4d54d18c912926e37eb28aa17c5d4f1c095b092d",
        ),
        (
            capture.SCENARIOS,
            "ed71d0bcc3c86c90523079814510871b401ae683199df54c413c01aab925b606",
        ),
    ]:
        assert (
            hashlib.sha256(
                capture.pinned.canonical_json_bytes(path.read_bytes())
            ).hexdigest()
            == digest
        )
    value = reference()
    capture.validate_result(value)
    assert value["source_commit"] == capture.SOURCE_COMMIT
    assert capture.SOURCE_COMMIT != capture.pinned.REVISION
    assert len(value["observations"]) == 123
    assert sum("error" in row for row in value["observations"]) == 54
    assert value["selected_definitions"][capture.pinned.ADAPTER] == [
        "CredentialDeliveryRecord",
        "_badgr_assertion_url",
        "_badgr_revoke_url",
        "_badgr_validation_url",
        "os",
        "quote",
    ]
    assert value["source_blobs"] == {
        "issuance.domain.entities": "1b5e2eba90c1ec13c1a38135f4da92813f1d1073",
        capture.pinned.ADAPTER: "c86671e2b2ab5bb8a72de78a9bdadb0f340a5ec8",
    }


def test_known_formatter_quote_and_error_observations_are_independent():
    rows = {v["id"]: v for v in reference()["observations"]}
    assert (
        rows["assertion-default"]["url"]
        == "https://api.example/v2/badgeclasses/badge%20%2F%E9%9B%AA%25/assertions"
    )
    assert (
        rows["validation-default"]["url"]
        == "https://api.example/v2/badgeclasses/badge%20%2F%E9%9B%AA%25"
    )
    assert (
        rows["revoke-default"]["url"]
        == "https://api.example/v2/assertions/award%20%2F%E9%9B%AA%25"
    )
    for operation in capture.HELPERS:
        assert rows[f"{operation}-literal-escaped"]["url"] == "/{literal}/{}"
        assert rows[f"{operation}-deterministic-attribute"]["url"] == "/str"
        assert rows[f"{operation}-position"]["error"]["type"] == "IndexError"
        assert rows[f"{operation}-missing-name"]["error"] == {
            "type": "KeyError",
            "message": "'missing'",
        }
        assert (
            rows[f"{operation}-quote-before-unused-format"]["error"]["type"]
            == "UnicodeEncodeError"
        )
        field = "external_credential_id" if operation == "revoke" else "badgeclass_id"
        assert rows[f"{operation}-no-recursive-replace"]["url"].startswith(
            "/{" + field + "}/"
        )
    assert (
        rows["validation-badge-missing"]["error"]["message"]
        == "CANVAS_CREDENTIALS_BADGECLASS_ID is required for Canvas Credentials validation"
    )
    assert (
        rows["assertion-badge-missing"]["error"]["message"]
        == "CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'"
    )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":1e9999}',
        b"{} {}",
        b"\xff",
        "{}".encode("utf-16"),
    ],
)
def test_outer_json_rejects_ambiguous_or_nonportable_values(raw):
    with pytest.raises((ValueError, UnicodeError)):
        capture.strict_json(raw)


@pytest.mark.parametrize(
    "fault",
    [
        "truncated",
        "duplicate",
        "wrong-id",
        "both-outcomes",
        "non-string",
        "provenance",
        "extra",
        "empty-closure",
    ],
)
def test_terminal_envelope_cannot_weaken_frozen_coverage(fault):
    value = deepcopy(reference())
    if fault == "truncated":
        value["observations"].pop()
    elif fault == "duplicate":
        value["observations"][1] = value["observations"][0]
    elif fault == "wrong-id":
        value["observations"][0]["id"] = "other"
    elif fault == "both-outcomes":
        value["observations"][0]["error"] = {"type": "ValueError", "message": "bad"}
    elif fault == "non-string":
        value["observations"][0]["url"] = None
    elif fault == "provenance":
        value["source_commit"] = "0" * 40
    elif fault == "empty-closure":
        value["source_blobs"] = {}
        value["selected_definitions"] = {}
    else:
        value["unreviewed"] = True
    with pytest.raises(ValueError):
        capture.validate_result(value)


@pytest.mark.parametrize(
    "mode", ["success", "nonzero", "stderr", "stdout-flood", "stderr-flood", "hang"]
)
def test_bounded_child_rejects_infrastructure_failures_even_with_valid_artifact(mode):
    encoded = json.dumps(reference(), ensure_ascii=True, allow_nan=False).encode()
    script = (
        "import sys,time\nsys.stdout.buffer.write("
        + repr(encoded)
        + ");sys.stdout.flush()\n"
    )
    if mode == "nonzero":
        script += "sys.exit(17)\n"
    elif mode == "stderr":
        script += "sys.stderr.write('synthetic-error')\n"
    elif mode.endswith("flood"):
        stream = "stdout" if mode.startswith("stdout") else "stderr"
        script += f"sys.{stream}.buffer.write(b'x'*300000);sys.{stream}.flush();time.sleep(10)\n"
    elif mode == "hang":
        script += "time.sleep(10)\n"
    command = [sys.executable, "-I", "-c", script]
    if mode == "success":
        assert capture.bounded_child(command, b"", timeout=2, cap=262144) == reference()
    else:
        expected = (
            "deadline"
            if mode == "hang"
            else "limit"
            if mode.endswith("flood")
            else "child failed"
        )
        with pytest.raises(RuntimeError, match=expected):
            capture.bounded_child(
                command, b"", timeout=0.5 if mode == "hang" else 2, cap=262144
            )


def test_reference_import_does_not_require_retired_runtime_dependencies():
    code = f"""
import importlib.abc,sys
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('fastapi','httpx','pydantic','sqlalchemy','issuance'):
            raise RuntimeError('Retired application dependency imported')
sys.meta_path.insert(0,Deny())
sys.path.insert(0,{str(SCRIPT.parent)!r})
import capture_canvas_url_template_reference
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=10
    )
    assert result.returncode == 0 and result.stderr == b""


def test_untrusted_source_and_unbounded_inputs_fail_before_child_spawn():
    with pytest.raises(ValueError, match="Untrusted observation source"):
        capture.pinned.verify_sources(
            {name: "synthetic" for name in capture.pinned.SOURCES}
        )
    for options in ({"timeout": 0}, {"cap": 0}, {"cap": 1}):
        with pytest.raises(ValueError, match="Invalid bounded template child inputs"):
            capture.bounded_child(["must-not-be-spawned"], b"xx", **options)


def test_caught_infrastructure_failure_is_not_recorded_as_helper_behavior():
    # Isolate the sticky audit control itself using a synthetic loader. No pinned
    # source substitutes enter the reference artifact or production capture.
    code = f"""
import sys,types
sys.path.insert(0,{str(SCRIPT.parent)!r})
import capture_canvas_url_template_reference as c
c.pinned.verify_sources=lambda sources: None
def helper(**arguments):
    sys.audit('socket.__new__',None,0,0,0)
    raise RuntimeError('synthetic helper error')
class Loader:
    selected=c.EXPECTED_DEFINITIONS
    def __init__(self,sources): pass
    def load(self,*args): return types.SimpleNamespace(**{{v[0]:helper for v in c.HELPERS.values()}})
    def validate_bindings(self): pass
    def close(self): pass
c.pinned.PinnedDefinitions=Loader
c.observe_sources({{}})
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=10
    )
    assert result.returncode != 0
    assert b"Infrastructure failure cannot become a helper observation" in result.stderr
