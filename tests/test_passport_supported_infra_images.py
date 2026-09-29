"""Disposable infrastructure pins require canonical digests and amd64 indexes."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil

import pytest

from scripts.passport_supported_infra_images import (
    ALLOWLIST, InfraImageError, qualified_images,
)


def policy(tmp_path: Path) -> tuple[Path, dict]:
    value = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    path = tmp_path / "infra.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


def index(reference: str) -> dict:
    return {"manifests": [{
        "digest": "sha256:" + "a" * 64,
        "platform": {"os": "linux", "architecture": "amd64"},
    }]}


def test_source_controlled_pins_are_canonical_and_complete(tmp_path: Path) -> None:
    path, value = policy(tmp_path)
    seen = []
    def inspect(reference: str) -> dict:
        seen.append(reference)
        return index(reference)
    result = qualified_images(path, inspect)
    assert result == {role: item["reference"]
                      for role, item in value["images"].items()}
    assert set(seen) == set(result.values())
    assert qualified_images(path, lambda _: pytest.fail("unexpected registry access"),
                            verify_registry=False) == result


@pytest.mark.parametrize("change,match", [
    (lambda value: value["images"]["postgres"].update(reference="postgres:15-alpine"),
     "pin"),
    (lambda value: value["images"]["redis"].update(
        reference="docker.io/library/postgres@sha256:" + "a" * 64), "pin"),
    (lambda value: value["images"]["openbao"].update(
        source_revision="unknown"), "pin"),
    (lambda value: value["images"].pop("redis"), "roles"),
    (lambda value: value.update(platform="windows/amd64"), "allowlist"),
])
def test_malformed_or_mutable_pin_is_rejected(tmp_path: Path, change, match: str) -> None:
    path, value = policy(tmp_path)
    change(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(InfraImageError, match=match):
        qualified_images(path, index)


def test_registry_must_contain_exact_supported_platform(tmp_path: Path) -> None:
    path, _ = policy(tmp_path)
    wrong = deepcopy(index("unused"))
    wrong["manifests"][0]["platform"]["architecture"] = "arm64"
    with pytest.raises(InfraImageError, match="linux/amd64"):
        qualified_images(path, lambda _: wrong)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Buildx unavailable")
def test_reviewed_registry_indexes_are_available_now() -> None:
    # Read-only registry smoke. It does not pull, run, or provision containers.
    assert set(qualified_images()) == {"postgres", "redis", "openbao", "edge"}
