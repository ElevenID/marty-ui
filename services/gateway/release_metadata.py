"""Public, non-secret runtime identity for release and demo evidence gates."""

from __future__ import annotations

import json
import os
from typing import Any

from gateway.middleware import MIP_VERSION


def _image_digests() -> dict[str, str]:
    raw = os.environ.get("ELEVENID_IMAGE_DIGESTS_JSON", "")
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    return {
        component: digest
        for component, digest in value.items()
        if isinstance(component, str) and isinstance(digest, str)
    }


def release_metadata() -> dict[str, Any]:
    release_version = os.environ.get("MARTY_RELEASE_VERSION", "development")
    return {
        "component": "services",
        "release_version": release_version,
        "deployment_release_marker": release_version,
        "stack_version": os.environ.get("ELEVENID_STACK_VERSION", "development"),
        "mip_version": MIP_VERSION,
        "marty_ui_sha": os.environ.get("MARTY_UI_SHA", "unknown"),
        "image_digests": _image_digests(),
    }
