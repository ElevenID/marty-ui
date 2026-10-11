"""Require reviewed KMS-only Core provenance at stack release boundaries."""

from __future__ import annotations

from typing import Any


CORE_REVISION = "6acba9d9e079cfba7ae9f94356899b29c93466b0"
CORE_VERSION = "0.2.0"
CORE_WHEEL_PREFIXES = {
    "marty-core-python": "marty_rs",
    "marty-verification-python": "marty_verification_py",
    "marty-iso18013-python": "marty_iso18013",
}
CORE_RELEASE_URI = (
    f"https://github.com/ElevenID/marty-core/releases/download/v{CORE_VERSION}/"
)


def has_hardened_core_wheels(components: list[dict[str, Any]]) -> bool:
    by_name = {component.get("name"): component for component in components}
    for name, wheel_prefix in CORE_WHEEL_PREFIXES.items():
        component = by_name.get(name)
        if not isinstance(component, dict) or (
            component.get("repository") != "ElevenID/marty-core"
            or component.get("commit") != CORE_REVISION
            or component.get("version") != CORE_VERSION
        ):
            return False
        artifacts = component.get("artifacts")
        if not isinstance(artifacts, list):
            return False
        wheels = [artifact for artifact in artifacts if artifact.get("type") == "python"]
        if len(wheels) != 1:
            return False
        uri = wheels[0].get("uri")
        if not isinstance(uri, str) or not (
            uri.startswith(CORE_RELEASE_URI + wheel_prefix + "-" + CORE_VERSION + "-")
            and uri.endswith(".whl")
        ):
            return False
    return True
