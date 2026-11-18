from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_public_protocol_documentation import (  # noqa: E402
    assert_documented_public_boundary,
)


def test_public_documentation_rejects_second_static_openapi_contract(tmp_path: Path) -> None:
    public = tmp_path / "ui/public"
    public.mkdir(parents=True)
    (public / "openapi.yaml").write_text("openapi: 3.1.0\npaths: {}\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="canonical /openapi.json"):
        assert_documented_public_boundary(tmp_path)


def test_public_documentation_rejects_stale_schema_download_links(tmp_path: Path) -> None:
    source = tmp_path / "ui/src"
    source.mkdir(parents=True)
    (source / "Download.jsx").write_text('<a href="/openapi.yaml">Download</a>', encoding="utf-8")
    with pytest.raises(AssertionError, match="links must use /openapi.json"):
        assert_documented_public_boundary(tmp_path)


def test_public_documentation_rejects_custody_selector_guidance(
    tmp_path: Path,
) -> None:
    (tmp_path / "obsolete.md").write_text(
        "Add a signing service selector to the credential template wizard.\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="private signing selectors"):
        assert_documented_public_boundary(tmp_path)


def test_public_documentation_can_describe_did_only_rejection(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "public-boundary.md").write_text(
        "Public APIs must never accept issuer_profile_id or signing_service_id; "
        "callers select only issuer_did.\n",
        encoding="utf-8",
    )

    assert_documented_public_boundary(tmp_path)
