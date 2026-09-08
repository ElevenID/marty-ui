"""Bind an explicit Kubernetes image to the reviewed issuance content digest.

No registry request, copy, attestation or deployment occurs here. A mirror must
retain the canonical manifest digest; availability is a separate operator gate.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys

if __package__:
    from .build_stack_manifest import validate_lock
    from .prepare_official_beta_release import OfficialReleaseError, image_reference
else:
    from build_stack_manifest import validate_lock
    from prepare_official_beta_release import OfficialReleaseError, image_reference

MAX_LOCK_BYTES = 1024 * 1024
MAX_REFERENCE_LENGTH = 4096
REFUSAL = (
    "Kubernetes issuance image must explicitly match the reviewed stack-lock digest."
)
CANONICAL_URI = "ghcr.io/elevenid/marty-credentials-issuance"
COMPONENT_NAME = "marty-credentials-issuance"
PATH_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError(REFUSAL)


def _registry_authority(authority: str) -> None:
    port = None
    if authority.startswith("["):
        closing = authority.find("]")
        _require(closing > 1)
        _require("%" not in authority[1:closing])
        ipaddress.IPv6Address(authority[1:closing])
        suffix = authority[closing + 1 :]
        _require(not suffix or suffix.startswith(":"))
        if suffix:
            port = suffix[1:]
    else:
        _require(authority.count(":") <= 1)
        host, separator, candidate_port = authority.partition(":")
        if separator:
            port = candidate_port
        _require(bool(host) and len(host) <= 253)
        _require(all(HOST_LABEL.fullmatch(label) for label in host.split(".")))
        # Docker otherwise interprets a bare first component as a namespace.
        _require("." in host or bool(separator) or host.lower() == "localhost")
        if re.fullmatch(r"[0-9.]+", host):
            ipaddress.IPv4Address(host)
    if port is not None:
        _require(bool(re.fullmatch(r"[0-9]{1,5}", port)))
        _require(1 <= int(port) <= 65535)


def validate_issuance_binding(reference: str, lock: dict) -> str:
    """Return the exact captured reference or a payload-free fixed error."""
    try:
        _require(isinstance(lock, dict))
        validate_lock(lock)
        _require(lock.get("release_state") == "eligible")
        candidates = [
            component
            for component in lock["components"]
            if component["name"] == COMPONENT_NAME
        ]
        _require(len(candidates) == 1)
        component = candidates[0]
        _require(component["repository"] == "ElevenID/marty-credentials")
        _require(isinstance(component["commit"], str))
        artifacts = [item for item in component["artifacts"] if item["type"] == "oci"]
        _require(len(artifacts) == 1)
        canonical = image_reference(artifacts[0], COMPONENT_NAME)
        _require(canonical["uri"] == CANONICAL_URI)
        _require(
            isinstance(reference, str) and 0 < len(reference) <= MAX_REFERENCE_LENGTH
        )
        _require(reference.count("@") == 1)
        repository, digest = reference.split("@")
        _require(len(repository) <= 255)
        _require(digest == canonical["digest"])
        authority, separator, path = repository.partition("/")
        _require(bool(separator) and bool(path))
        _registry_authority(authority)
        _require(all(PATH_COMPONENT.fullmatch(part) for part in path.split("/")))
    except (ValueError, TypeError, KeyError, AttributeError, OfficialReleaseError):
        raise ValueError(REFUSAL) from None
    return reference


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _finite_float(value):
    parsed = float(value)
    _require(math.isfinite(parsed))
    return parsed


def _reject_constant(_value):
    raise ValueError(REFUSAL)


def main() -> int:
    try:
        _require(len(sys.argv) == 1)
        reference = os.environ.get("MARTY_ISSUANCE_IMAGE", "")
        lock_path = Path(__file__).resolve().parents[1] / "release/stack-lock.json"
        with lock_path.open("rb") as source:
            data = source.read(MAX_LOCK_BYTES + 1)
        _require(len(data) <= MAX_LOCK_BYTES)
        lock = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
        selected = validate_issuance_binding(reference, lock)
    except (ValueError, TypeError, RecursionError, OSError):
        print(REFUSAL, file=sys.stderr)
        return 1
    # Preserve the exact validated reference under both POSIX and Git Bash:
    # Windows text newline translation must not append CR to shell capture.
    sys.stdout.buffer.write((selected + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
