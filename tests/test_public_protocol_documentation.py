from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_public_protocol_contract import _assert_documented_public_boundary  # noqa: E402


def test_public_documentation_rejects_custody_selector_guidance(
    tmp_path: Path,
) -> None:
    (tmp_path / "obsolete.md").write_text(
        "Add a signing service selector to the credential template wizard.\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError, match="private signing selectors"):
        _assert_documented_public_boundary(tmp_path)


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

    _assert_documented_public_boundary(tmp_path)
