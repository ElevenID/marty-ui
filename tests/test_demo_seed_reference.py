"""The live demo seed commands must work without the retired Python package."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = json.loads(
    (ROOT / "contracts/demo-seed-reference-v1.json").read_text(encoding="utf-8")
)


def test_demo_seed_reference_keeps_released_identifiers_and_catalog() -> None:
    assert REFERENCE["schema"] == "marty.demo-seed-reference/v1"
    assert REFERENCE["source"]["commit"] == "36bb2aac65759edc2ccdce120e16a61391a7ce32"
    ids = REFERENCE["canvas_system_ids"]
    assert ids == {
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID":
            "0ab66d45-0d84-5fbd-837f-25788d3227a1",
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID":
            "50000000-0000-0000-0000-000000000041",
        "MARTY_DEFAULT_ORG_ID": "00000000-0000-0000-0000-000000000001",
        "MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID":
            "0ab66d45-0d84-5fbd-837f-25788d32279e",
        "MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID":
            "50000000-0000-0000-0000-000000000040",
    }
    bundle = REFERENCE["vendor_bundle"]
    assert bundle["organization"]["id"] == "22222222-2222-2222-2222-222222222222"
    assert len(bundle["credential_types"]) == 7
    assert len(bundle["credential_templates"]) == 8


def test_provenance_uses_canonical_git_blob_bytes() -> None:
    source = REFERENCE["source"]
    source_paths = {
        "system_ids_sha256": (
            "packages/marty-common/marty_common/system_ids.py",
            "5dcac6ed7719d0bdc32e8948a2ce803112c660a7b0ecd04164fed0ff562f5717",
        ),
        "demo_seed_data_sha256": (
            "packages/marty-common/marty_common/demo_seed_data.py",
            "2c4b71cdc775e167e10e9b47e5b629dcf53b3e771dd6769f135dbb8a12d1bc83",
        ),
    }
    marty_checkout = ROOT.parent / "Marty"
    for field, (path, expected) in source_paths.items():
        assert source[field] == expected
        if (marty_checkout / ".git").exists():
            blob = subprocess.run(
                ["git", "-C", str(marty_checkout), "show", f"{source['commit']}:{path}"],
                capture_output=True,
                check=True,
            ).stdout
            assert hashlib.sha256(blob).hexdigest() == expected


def test_canvas_seed_make_target_uses_packaged_rust_runner() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("canvas-real-seed:", 1)[1].split("canvas-real-bootstrap:", 1)[0]
    assert 'bash scripts/run-canvas-real-seed.sh "$(BETA_ENV_FILE)"' in target
    assert "seed_canvas_real.py" not in target


def test_canvas_seed_runner_forwards_shell_flags_and_uses_internal_services() -> None:
    git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
    bash = str(git_bash) if os.name == "nt" and git_bash.exists() else "bash"
    command = (
        "docker() { :; }; "
        "source scripts/run-canvas-real-seed.sh .env.example"
    )
    result = subprocess.run(
        [bash, "-x", "-c", command],
        cwd=ROOT,
        env={**os.environ, "CANVAS_DEMO_EVIDENCE_EVENT_ENABLED": "true", "MARTY_API_KEY": "test-key"},
        capture_output=True,
        text=True,
        check=True,
    )
    trace = result.stderr
    assert "--env CANVAS_DEMO_EVIDENCE_EVENT_ENABLED" in trace
    assert "--env MARTY_API_KEY" in trace
    assert "--env SIGNING_KEYS_INTERNAL_BASE_URL=http://signing-keys:8017/internal/signing-keys" in trace
    assert "--env SIGNING_KEYS_HOLDER_PROOF_BASE_URL=http://signing-keys:8017/internal/signing-keys" in trace
    assert "db-migrate /usr/local/bin/marty-canvas-demo-seed --env-file /dev/null" in trace
