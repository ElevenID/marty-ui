from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY_OVERRIDES = {
    "browserslist": "4.28.9",
    "fast-uri": "4.1.4",
    "qs": "6.16.0",
}


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_ui_security_overrides_are_pinned_in_both_lockfiles() -> None:
    package = json.loads(_text("ui/package.json"))
    npm_lock = json.loads(_text("ui/package-lock.json"))
    bun_lock = _text("ui/bun.lock")
    bun_overrides = bun_lock.split('  "overrides": {', 1)[1].split(
        '  "packages": {', 1
    )[0]

    for dependency, version in SECURITY_OVERRIDES.items():
        assert package["overrides"][dependency] == version
        assert npm_lock["packages"][f"node_modules/{dependency}"]["version"] == version
        assert f'"{dependency}": "{version}"' in bun_overrides
        assert re.search(
            rf'^    "{re.escape(dependency)}": '
            rf'\["{re.escape(dependency)}@{re.escape(version)}"',
            bun_lock,
            re.MULTILINE,
        )


def test_security_job_rejects_a_stale_bun_lock_before_auditing() -> None:
    workflow = _text(".github/workflows/ci.yml")

    assert (
        "bun install --frozen-lockfile --ignore-scripts && bun audit"
        in workflow
    )
