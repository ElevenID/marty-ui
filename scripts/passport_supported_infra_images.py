#!/usr/bin/env python3
"""Qualify immutable infrastructure images for disposable passport plans."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "deploy-config/passport-supported-disposable-infra-images.json"
ROLES = {
    "postgres": "docker.io/library/postgres",
    "redis": "docker.io/library/redis",
    "openbao": "quay.io/openbao/openbao",
    "edge": "docker.io/library/nginx",
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class InfraImageError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise InfraImageError(message)


def registry_index(reference: str) -> dict:
    candidates = [reference]
    if reference.startswith("docker.io/library/"):
        candidates.insert(0, reference.replace("docker.io/", "mirror.gcr.io/", 1))
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            result = subprocess.run(
                ["docker", "buildx", "imagetools", "inspect", candidate, "--raw"],
                check=True, capture_output=True, text=True, encoding="utf-8",
                timeout=60,
            )
            require(len(result.stdout) <= 4 * 1024 * 1024,
                    "Infrastructure registry index is oversized")
            index = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            last_error = exc
            continue
        require(isinstance(index, dict), "Infrastructure registry index is invalid")
        return index
    raise InfraImageError("Infrastructure registry digest is unavailable") from last_error


def qualified_images(
    path: Path = ALLOWLIST,
    inspect: Callable[[str], dict] = registry_index,
    *, verify_registry: bool = True,
) -> dict[str, str]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InfraImageError("Disposable infrastructure allowlist is missing") from exc
    require(isinstance(policy, dict)
            and policy.get("schema") == "marty.passport-supported-disposable-infra-images/v1"
            and policy.get("scope") == "disposable-passport-acceptance-only"
            and policy.get("platform") == "linux/amd64",
            "Disposable infrastructure allowlist is invalid")
    images = policy.get("images")
    require(isinstance(images, dict) and set(images) == set(ROLES),
            "Disposable infrastructure roles are incomplete")
    result: dict[str, str] = {}
    for role, repository in ROLES.items():
        item = images[role]
        require(isinstance(item, dict)
                and set(item) == {"reference", "version", "source_revision"},
                "Disposable infrastructure image metadata is invalid")
        reference = item["reference"]
        require(isinstance(reference, str)
                and reference.startswith(repository + "@")
                and DIGEST.fullmatch(reference.removeprefix(repository + "@")) is not None
                and isinstance(item["version"], str)
                and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9.]+)?",
                                 item["version"]) is not None
                and isinstance(item["source_revision"], str)
                and COMMIT.fullmatch(item["source_revision"]) is not None,
                "Disposable infrastructure image pin is invalid")
        if verify_registry:
            index = inspect(reference)
            manifests = index.get("manifests") if isinstance(index, dict) else None
            matching = [entry for entry in manifests if
                isinstance(entry, dict)
                and isinstance(entry.get("platform"), dict)
                and entry["platform"].get("os") == "linux"
                and entry["platform"].get("architecture") == "amd64"
                and isinstance(entry.get("digest"), str)
                and DIGEST.fullmatch(entry["digest"]) is not None
                ] if isinstance(manifests, list) else []
            require(len(matching) == 1,
                "Disposable infrastructure image lacks linux/amd64 registry manifest")
            annotations = matching[0].get("annotations", {})
            require(isinstance(annotations, dict),
                    "Disposable infrastructure registry annotations are invalid")
            revision = annotations.get("org.opencontainers.image.revision")
            version = annotations.get("org.opencontainers.image.version")
            require(revision in (None, item["source_revision"])
                    and version in (None, item["version"]),
                    "Disposable infrastructure source/version differs from reviewed pin")
        result[role] = reference
    return result
