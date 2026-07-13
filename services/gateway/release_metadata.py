"""Public, non-secret runtime identity for release-gate provenance checks."""

from __future__ import annotations

import os


def release_metadata() -> dict[str, str]:
    return {
        "component": "services",
        "release_version": os.environ.get("MARTY_RELEASE_VERSION", "development"),
        "marty_ui_sha": os.environ.get("MARTY_UI_SHA", "unknown"),
    }
