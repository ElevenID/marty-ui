#!/usr/bin/env python3
"""Resolve the recorder commit bound to an exact governed beta deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


SHA = re.compile(r"[0-9a-f]{40}\Z")
RECORDER_URL = "https://github.com/ElevenID/marty-demo-recorder"


def _read(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError(f"Invalid deployment evidence file: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid deployment evidence object: {path.name}")
    return data


def recorder_commit(artifact_dir: Path, expected_ui_commit: str) -> str:
    if SHA.fullmatch(expected_ui_commit) is None:
        raise ValueError("Expected UI commit is invalid")
    source = _read(artifact_dir / "source-manifest.json")
    deployment = _read(artifact_dir / "local-deployment-manifest.json")
    demo_path = artifact_dir / "deployed-demo-manifest.json"
    demo = _read(demo_path)
    components = source.get("component_revisions")
    if not isinstance(components, list):
        raise ValueError("Source component revisions are missing")
    matches = [entry for entry in components if isinstance(entry, dict)
               and entry.get("component") == "marty-demo-recorder"]
    if (len(matches) != 1 or matches[0].get("repository") != RECORDER_URL
            or SHA.fullmatch(str(matches[0].get("revision", ""))) is None):
        raise ValueError("Recorder source revision is missing or ambiguous")
    revision = matches[0]["revision"]
    digest = hashlib.sha256(demo_path.read_bytes()).hexdigest()
    if not (
        source.get("source_kind") == "official-stack-release"
        and source.get("marty_ui_sha") == expected_ui_commit
        and deployment.get("source_kind") == "official-stack-release"
        and deployment.get("marty_ui_sha") == expected_ui_commit
        and deployment.get("source_manifest") == "source-manifest.json"
        and deployment.get("deployed_demo_manifest") == "deployed-demo-manifest.json"
        and deployment.get("deployed_demo_manifest_sha256") == digest
        and deployment.get("component_revisions", {}).get("marty-demo-recorder") == revision
        and source.get("repositories", {}).get("marty-demo-recorder") == {
            "repository": RECORDER_URL,
            "revision": revision,
            "source": "explicit-recorder-revision",
        }
        and demo.get("demo_application_revision") == expected_ui_commit
        and demo.get("recorder_revision") == {"kind": "git", "value": revision}
        and demo.get("release_evidence", {}).get("source_marker") == expected_ui_commit
    ):
        raise ValueError("Recorder revision does not match the governed beta deployment")
    return revision


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--expected-ui-commit", required=True)
    args = parser.parse_args()
    try:
        print(recorder_commit(args.artifact_dir, args.expected_ui_commit))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Recorder pin blocked: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
