from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "scripts" / "release_version.py"
SPEC = importlib.util.spec_from_file_location("release_version", MODULE_PATH)
release_version = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(release_version)


def test_validate_release_tag_accepts_calver_and_rc_tags():
    assert release_version.validate_release_tag("2026.05.0") == "2026.05.0"
    assert release_version.validate_release_tag("2026.05.0-rc.1") == "2026.05.0-rc.1"


@pytest.mark.parametrize("tag", ["latest", "prod", "main", "dev"])
def test_validate_release_tag_rejects_mutable_aliases(tag: str):
    with pytest.raises(release_version.ReleaseVersionError):
        release_version.validate_release_tag(tag)


@pytest.mark.parametrize("tag", ["2026.5.0", "2026.13.0", "1.0.0", "release-2026.05.0"])
def test_validate_release_tag_rejects_invalid_formats(tag: str):
    with pytest.raises(release_version.ReleaseVersionError):
        release_version.validate_release_tag(tag)


def test_resolve_release_tag_reads_version_file_when_tag_missing(tmp_path):
    (tmp_path / "VERSION").write_text("2026.06.1\n", encoding="utf-8")

    assert release_version.resolve_release_tag(repo_root=tmp_path) == "2026.06.1"


def test_resolve_release_tag_prefers_explicit_tag_over_version_file(tmp_path):
    (tmp_path / "VERSION").write_text("2026.06.1\n", encoding="utf-8")

    assert release_version.resolve_release_tag(repo_root=tmp_path, tag="2026.07.0") == "2026.07.0"
