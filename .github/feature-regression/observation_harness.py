"""Check the captured Rust probe against the repository's exact public oracle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "tests/test_feature_regression_rust_probe.py"
REVISION = re.compile(r"[0-9a-f]{40}\Z")
DIMENSIONS = {"public_status", "public_message", "safe_server_diagnostic"}
MAX_CAPTURE_BYTES = 1_048_576
REFERENCE_SUFFIX = "tests/test_feature_regression_rust_probe.py::assert_expected_probe_output"


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _read_capture() -> list[dict[str, object]]:
    raw = sys.stdin.buffer.read(MAX_CAPTURE_BYTES + 1)
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds bound")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    if not isinstance(capture, dict) or set(capture) != {"schema", "receipt", "observations"}:
        raise ValueError("capture fields are invalid")
    if capture["schema"] != "elevenid.behavior-subject-capture/v2":
        raise ValueError("capture schema is invalid")
    receipt = capture["receipt"]
    observations = capture["observations"]
    if not isinstance(receipt, dict) or not isinstance(observations, list):
        raise ValueError("capture content is invalid")
    if receipt.get("runtime") != "rust-cargo" or receipt.get("stderr_sha256") != "sha256:" + hashlib.sha256(b"").hexdigest():
        raise ValueError("capture runtime or stderr is invalid")
    subject = {"schema": "elevenid.behavior-subject-output/v2", "observations": observations}
    subject_bytes = _canonical(subject)
    if receipt.get("stdout_sha256") != "sha256:" + hashlib.sha256(subject_bytes).hexdigest():
        raise ValueError("capture stdout digest is invalid")
    if ORACLE.is_symlink() or not ORACLE.is_file():
        raise ValueError("oracle is not a regular file")
    spec = importlib.util.spec_from_file_location("elevenid_feature_regression_probe_oracle", ORACLE)
    if spec is None or spec.loader is None:
        raise ValueError("oracle cannot be loaded")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    oracle.assert_expected_probe_output(subject_bytes)
    identities = {(item["case_id"], item["dimension"]) for item in observations}
    if len(identities) != len(observations) or any(item["dimension"] not in DIMENSIONS for item in observations):
        raise ValueError("capture identities are invalid")
    return observations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("test", "emit"))
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--repository")
    parser.add_argument("--revision")
    args = parser.parse_args()
    observations = _read_capture()
    if args.command == "test":
        return
    if args.repository != "ElevenID/marty-ui" or not isinstance(args.revision, str) or REVISION.fullmatch(args.revision) is None:
        raise ValueError("target identity is invalid")
    reference = f"test:{args.repository}@{args.revision}:{REFERENCE_SUFFIX}"
    output = {
        "schema": "elevenid.behavior-observations-runtime/v2",
        "repository": args.repository,
        "revision": args.revision,
        "phase": args.phase,
        "observations": [
            {**item, "id": f"{item['case_id']}.{item['dimension']}.{args.phase}", "producer_test": reference}
            for item in observations
        ],
    }
    sys.stdout.buffer.write(_canonical(output))


if __name__ == "__main__":
    main()
