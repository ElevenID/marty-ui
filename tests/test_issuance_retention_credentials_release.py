from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.check_didcomm_native_credentials_release import NativeDidcommReleaseError
from scripts.check_issuance_retention_credentials_release import (
    REQUIRED_COMMIT,
    REQUIRED_REVISION,
    REQUIRED_VERSION,
    validate_retention_release,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/didcomm-native-consumer-ownership.json").read_text(
        encoding="utf-8"
    )
)
LOCK = json.loads((ROOT / "release/stack-lock.json").read_text(encoding="utf-8"))


def test_retention_requires_the_reviewed_event_owner_migration_release() -> None:
    assert REQUIRED_VERSION == "0.1.78"
    assert REQUIRED_REVISION == "issuance_event_owner"
    assert REQUIRED_COMMIT == "efd5da1e2d41419ce93721f98d314c7b911e6b5e"
    assert CONTRACT["release_gate"]["qualified_release"]["commit"] == REQUIRED_COMMIT
    validate_retention_release(CONTRACT, LOCK)


def test_retention_rejects_previous_didcomm_compatible_release() -> None:
    contract, lock = deepcopy(CONTRACT), deepcopy(LOCK)
    release = contract["release_gate"]["qualified_release"]
    release["version"] = "0.1.77"
    release["evidence"]["sbom"] = release["evidence"]["sbom"].replace(
        "v0.1.78", "v0.1.77"
    )
    component = next(
        item for item in lock["components"] if item["name"] == "marty-credentials-issuance"
    )
    component["version"] = "0.1.77"
    component["artifacts"][0]["sbom"] = release["evidence"]["sbom"]
    with pytest.raises(NativeDidcommReleaseError, match="Native retention requires"):
        validate_retention_release(contract, lock)


def test_retention_rejects_an_unreviewed_coherent_source_pin() -> None:
    contract, lock = deepcopy(CONTRACT), deepcopy(LOCK)
    unreviewed_commit = "a" * 40
    gate = contract["release_gate"]
    gate["required_source_checkpoint"] = unreviewed_commit
    gate["qualified_release"]["commit"] = unreviewed_commit
    gate["qualified_release"]["evidence"]["provenance_source_commit"] = (
        unreviewed_commit
    )
    component = next(
        item for item in lock["components"] if item["name"] == "marty-credentials-issuance"
    )
    component["commit"] = unreviewed_commit
    with pytest.raises(NativeDidcommReleaseError, match="Native retention requires"):
        validate_retention_release(contract, lock)


def test_retention_release_gate_runs_in_ci_and_cd() -> None:
    invocation = "python scripts/check_issuance_retention_credentials_release.py"
    for workflow in ("ci.yml", "cd.yml"):
        assert invocation in (ROOT / ".github/workflows" / workflow).read_text(
            encoding="utf-8"
        )
