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


def test_vitest_suite_excludes_redirect_mock_file_read_advisory() -> None:
    # GHSA-82fw-gwwq-j7x9: both vitest and @vitest/mocker require 4.1.11.
    package = json.loads(_text("ui/package.json"))
    npm_lock = json.loads(_text("ui/package-lock.json"))
    bun_lock = _text("ui/bun.lock")
    suite = ("vitest", "@vitest/ui", "@vitest/coverage-v8")
    versions = set()

    for dependency in (*suite, "@vitest/mocker"):
        version = npm_lock["packages"][f"node_modules/{dependency}"]["version"]
        assert re.fullmatch(r"\d+\.\d+\.\d+", version)
        assert tuple(map(int, version.split("."))) >= (4, 1, 11)
        versions.add(version)
        assert re.search(
            rf'^    "{re.escape(dependency)}": '
            rf'\["{re.escape(dependency)}@{re.escape(version)}"',
            bun_lock,
            re.MULTILINE,
        )

    assert len(versions) == 1, "Vitest runner, UI, coverage and mocker must agree"
    for dependency in suite:
        requirement = package["devDependencies"][dependency]
        assert re.fullmatch(r"\^\d+\.\d+\.\d+", requirement)
        assert tuple(map(int, requirement[1:].split("."))) >= (4, 1, 11)
        assert npm_lock["packages"][""]["devDependencies"][dependency] == requirement
        assert f'"{dependency}": "{requirement}"' in bun_lock.split(
            '  "packages": {', 1
        )[0]


def test_no_nested_vitest_or_mocker_copies_retain_the_advisory() -> None:
    npm_lock = json.loads(_text("ui/package-lock.json"))
    bun_lock = _text("ui/bun.lock")
    for dependency in ("vitest", "@vitest/mocker"):
        npm_versions = [
            metadata["version"]
            for path, metadata in npm_lock["packages"].items()
            if path.endswith(f"node_modules/{dependency}")
        ]
        bun_versions = re.findall(
            rf'^    "[^"]+": \["{re.escape(dependency)}@([^"]+)"',
            bun_lock,
            re.MULTILINE,
        )
        assert npm_versions and bun_versions
        for version in (*npm_versions, *bun_versions):
            assert re.fullmatch(r"\d+\.\d+\.\d+", version)
            assert tuple(map(int, version.split("."))) >= (4, 1, 11)
