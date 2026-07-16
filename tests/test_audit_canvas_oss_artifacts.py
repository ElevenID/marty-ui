from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.audit_canvas_oss_artifacts import audit_artifacts


ROOT = Path(__file__).resolve().parents[1]


def test_artifact_audit_rejects_credentials_and_private_jwk(tmp_path: Path) -> None:
    cases = {
        "session.json": {"session_token": "secret"},
        "config.json": {"client_secret": "secret"},
        "api.json": {"api_key": "secret"},
        "login.json": {"password": "secret"},
        "jwk.json": {"kty": "RSA", "d": "private"},
        "jwt.txt": "eyJabcdefghijk.eyJabcdefghijk.abcdefghijk",
    }
    for name, value in cases.items():
        path = tmp_path / name
        path.write_text(json.dumps(value) if isinstance(value, dict) else value, encoding="utf-8")
    failures = audit_artifacts(tmp_path)
    assert len(failures) == len(cases)


def test_artifact_audit_accepts_fixed_sanitized_result(tmp_path: Path) -> None:
    (tmp_path / "portable-attestation.json").write_text(
        json.dumps({"status": "passed", "attestation": {"rails_runner_calls": 0}}),
        encoding="utf-8",
    )
    assert audit_artifacts(tmp_path) == []


def test_staging_never_copies_unlisted_failure_output(tmp_path: Path) -> None:
    source = tmp_path / "raw"
    output = tmp_path / "staged"
    source.mkdir()
    (source / "runtime-context.json").write_text('{"schema_version": 1}', encoding="utf-8")
    (source / "contract-driver-manifest.json").write_text(
        '{"schema_version": 1, "execution_boundary": "docker_compose_one_shot"}',
        encoding="utf-8",
    )
    (source / "debug.log").write_text("harmless but not uploadable", encoding="utf-8")
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/stage_canvas_oss_artifacts.py"),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=True,
    )
    assert (output / "runtime-context.json").is_file()
    assert (output / "contract-driver-manifest.json").is_file()
    assert not (output / "debug.log").exists()
    assert (output / "artifact-manifest.json").is_file()
