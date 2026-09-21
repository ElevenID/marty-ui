#!/usr/bin/env python3
"""Block native DIDComm activation without its exact Credentials image."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts" / "didcomm-native-consumer-ownership.json"
DEFAULT_LOCK = ROOT / "release" / "stack-lock.json"
COMMIT = re.compile(r"[0-9a-f]{40}$")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"\d+\.\d+\.\d+$")
COMPONENT = "marty-credentials-issuance"
REPOSITORY = "ElevenID/marty-credentials"
IMAGE = "ghcr.io/elevenid/marty-credentials-issuance"


class NativeDidcommReleaseError(RuntimeError):
    """The selected native owner lacks an exact compatible release artifact."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeDidcommReleaseError(message)


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeDidcommReleaseError(f"Could not read {path.name}: {exc}") from exc
    _require(isinstance(value, dict), f"{path.name} must contain a JSON object")
    return value


def _version_tuple(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or VERSION.fullmatch(value) is None:
        return None
    return tuple(int(part) for part in value.split("."))


def validate_release_gate(contract: dict[str, Any], lock: dict[str, Any]) -> None:
    """Require one exact qualified image before selected native models can land."""

    _require(
        contract.get("schema") == "marty.didcomm-native-consumer-ownership/v1",
        "Native DIDComm ownership contract schema is invalid",
    )
    selected = contract.get("selected_compose_models")
    _require(
        isinstance(selected, list) and bool(selected),
        "No native DIDComm owner is selected",
    )
    gate = contract.get("release_gate")
    _require(
        isinstance(gate, dict), "Native DIDComm Credentials release gate is missing"
    )
    checkpoint = gate.get("required_source_checkpoint")
    _require(
        isinstance(checkpoint, str) and COMMIT.fullmatch(checkpoint) is not None,
        "Native DIDComm Credentials source checkpoint is invalid",
    )
    minimum_version = gate.get("minimum_version")
    minimum_version_tuple = _version_tuple(minimum_version)
    _require(
        minimum_version_tuple is not None,
        "Native DIDComm minimum Credentials version is invalid",
    )

    components = lock.get("components")
    _require(isinstance(components, list), "Stack lock components are missing")
    matches = [item for item in components if item.get("name") == COMPONENT]
    _require(
        len(matches) == 1, "Stack lock must contain one Credentials issuance image"
    )
    component = matches[0]
    _require(
        component.get("repository") == REPOSITORY, "Credentials repository is incorrect"
    )
    artifacts = component.get("artifacts")
    _require(
        isinstance(artifacts, list) and len(artifacts) == 1,
        "Credentials image is ambiguous",
    )
    artifact = artifacts[0]
    _require(
        artifact.get("type") == "oci" and artifact.get("uri") == IMAGE,
        "Credentials issuance artifact is not the canonical OCI image",
    )

    if gate.get("state") != "qualified":
        _require(
            gate.get("qualified_release") is None,
            "Pending native DIDComm gate must not contain a release pin",
        )
        raise NativeDidcommReleaseError(
            "Native DIDComm activation is blocked until a compatible immutable "
            "Credentials release pins its exact version, source commit, and digest"
        )

    release = gate.get("qualified_release")
    _require(
        isinstance(release, dict), "Qualified native DIDComm release pin is missing"
    )
    version = release.get("version")
    commit = release.get("commit")
    digest = release.get("digest")
    version_tuple = _version_tuple(version)
    _require(
        version_tuple is not None,
        "Qualified Credentials version is invalid",
    )
    _require(
        version_tuple >= minimum_version_tuple,
        "Qualified Credentials version predates native DIDComm ownership",
    )
    _require(
        isinstance(commit, str) and COMMIT.fullmatch(commit) is not None,
        "Qualified Credentials commit is invalid",
    )
    _require(
        commit == checkpoint,
        "Qualified Credentials release commit is not the reviewed checkpoint",
    )
    _require(
        isinstance(digest, str) and DIGEST.fullmatch(digest) is not None,
        "Qualified Credentials digest is invalid",
    )
    _require(
        component.get("version") == version, "Stack lock Credentials version is stale"
    )
    _require(
        component.get("commit") == commit, "Stack lock Credentials commit is stale"
    )
    _require(artifact.get("digest") == digest, "Stack lock Credentials digest is stale")


def check_release_gate(contract_path: Path, lock_path: Path) -> None:
    validate_release_gate(_load(contract_path), _load(lock_path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    args = parser.parse_args()
    try:
        check_release_gate(args.contract, args.lock)
    except NativeDidcommReleaseError as exc:
        print(f"Native DIDComm Credentials release gate failed: {exc}")
        return 1
    print("Native DIDComm Credentials release gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
