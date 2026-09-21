from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.check_didcomm_native_credentials_release import (
    IMAGE,
    NativeDidcommReleaseError,
    PROVENANCE,
    RELEASE_BASE,
    SBOM_NAME,
    validate_release_gate,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/didcomm-native-consumer-ownership.json").read_text(
        encoding="utf-8"
    )
)
LOCK = json.loads((ROOT / "release/stack-lock.json").read_text(encoding="utf-8"))


def _component(lock: dict) -> dict:
    matches = [
        item
        for item in lock["components"]
        if item["name"] == "marty-credentials-issuance"
    ]
    assert len(matches) == 1
    return matches[0]


def _qualified_models() -> tuple[dict, dict]:
    contract = deepcopy(CONTRACT)
    lock = deepcopy(LOCK)
    # Test-only values exercise the validator independently of the published pin.
    version = "0.1.76"
    commit = contract["release_gate"]["required_source_checkpoint"]
    digest = "sha256:" + "a" * 64
    sbom = f"{RELEASE_BASE}/v{version}/{SBOM_NAME}"
    release = {
        "version": version,
        "commit": contract["release_gate"]["required_source_checkpoint"],
        "digest": digest,
        "evidence": {
            "sbom": sbom,
            "provenance": PROVENANCE,
            "provenance_subject": f"{IMAGE}@{digest}",
            "provenance_source_commit": commit,
        },
    }
    contract["release_gate"].update(state="qualified", qualified_release=release)
    component = _component(lock)
    component.update(version=release["version"], commit=release["commit"])
    component["artifacts"][0].update(
        digest=release["digest"], sbom=sbom, provenance=PROVENANCE
    )
    return contract, lock


def test_current_activation_is_bound_to_the_exact_published_release() -> None:
    gate = CONTRACT["release_gate"]
    assert gate["state"] == "qualified"
    assert gate["required_source_checkpoint"] == (
        "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"
    )
    assert gate["minimum_version"] == "0.1.76"
    release = gate["qualified_release"]
    assert release == {
        "version": "0.1.76",
        "commit": "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26",
        "digest": (
            "sha256:815cbba6efc7c91e770a8dd15fe5fa102d252a485073bf60f0e0d5e0a73b28e5"
        ),
        "evidence": {
            "sbom": f"{RELEASE_BASE}/v0.1.76/{SBOM_NAME}",
            "provenance": PROVENANCE,
            "provenance_subject": (
                f"{IMAGE}@sha256:815cbba6efc7c91e770a8dd15fe5fa102d252a485"
                "073bf60f0e0d5e0a73b28e5"
            ),
            "provenance_source_commit": ("aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"),
        },
    }
    component = _component(LOCK)
    assert {
        "version": component["version"],
        "commit": component["commit"],
        "digest": component["artifacts"][0]["digest"],
    } == {
        "version": release["version"],
        "commit": release["commit"],
        "digest": release["digest"],
    }
    validate_release_gate(CONTRACT, LOCK)


def test_pending_gate_still_fails_closed_without_a_release_pin() -> None:
    contract = deepcopy(CONTRACT)
    contract["release_gate"].update(
        state="blocked_pending_credentials_release", qualified_release=None
    )
    with pytest.raises(NativeDidcommReleaseError, match="activation is blocked"):
        validate_release_gate(contract, LOCK)


def test_exact_synthetic_release_pin_can_satisfy_the_closed_gate() -> None:
    contract, lock = _qualified_models()
    validate_release_gate(contract, lock)


@pytest.mark.parametrize("version", ["0.1.72", "0.1.74", "0.1.75"])
def test_stale_failed_or_quarantined_release_versions_fail_closed(
    version: str,
) -> None:
    contract, lock = _qualified_models()
    release = contract["release_gate"]["qualified_release"]
    release["version"] = version
    release["evidence"]["sbom"] = f"{RELEASE_BASE}/v{version}/{SBOM_NAME}"
    component = _component(lock)
    component["version"] = version
    component["artifacts"][0]["sbom"] = release["evidence"]["sbom"]
    with pytest.raises(NativeDidcommReleaseError, match="predates"):
        validate_release_gate(contract, lock)


@pytest.mark.parametrize(
    "mutation",
    ["version", "commit", "digest", "checkpoint", "release_commit", "image"],
)
def test_partial_stale_or_wrong_release_pins_fail_closed(mutation: str) -> None:
    contract, lock = _qualified_models()
    component = _component(lock)
    if mutation == "version":
        contract["release_gate"]["qualified_release"]["version"] = "0.1.74"
        component["version"] = "0.1.74"
    elif mutation == "commit":
        component["commit"] = "b" * 40
    elif mutation == "digest":
        component["artifacts"][0]["digest"] = "sha256:" + "b" * 64
    elif mutation == "checkpoint":
        contract["release_gate"]["required_source_checkpoint"] = "c" * 40
    elif mutation == "release_commit":
        contract["release_gate"]["qualified_release"]["commit"] = "c" * 40
        component["commit"] = "c" * 40
    else:
        component["artifacts"][0]["uri"] = "ghcr.io/elevenid/unreviewed"
    with pytest.raises(NativeDidcommReleaseError):
        validate_release_gate(contract, lock)


@pytest.mark.parametrize(
    "mutation",
    [
        "release_sbom",
        "lock_sbom",
        "release_provenance",
        "lock_provenance",
        "provenance_subject",
        "provenance_source_commit",
    ],
)
def test_stale_or_wrong_release_evidence_fails_closed(mutation: str) -> None:
    contract, lock = _qualified_models()
    release = contract["release_gate"]["qualified_release"]
    evidence = release["evidence"]
    artifact = _component(lock)["artifacts"][0]
    if mutation == "release_sbom":
        evidence["sbom"] = f"{RELEASE_BASE}/v0.1.72/{SBOM_NAME}"
    elif mutation == "lock_sbom":
        artifact["sbom"] = f"{RELEASE_BASE}/v0.1.72/{SBOM_NAME}"
    elif mutation == "release_provenance":
        evidence["provenance"] = "https://example.invalid/attestations"
    elif mutation == "lock_provenance":
        artifact["provenance"] = "https://example.invalid/attestations"
    elif mutation == "provenance_subject":
        evidence["provenance_subject"] = f"{IMAGE}@sha256:{'b' * 64}"
    else:
        evidence["provenance_source_commit"] = "b" * 40
    with pytest.raises(NativeDidcommReleaseError):
        validate_release_gate(contract, lock)


def test_ci_and_cd_execute_the_unbypassable_release_gate() -> None:
    invocation = "python scripts/check_didcomm_native_credentials_release.py"
    assert invocation in (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert invocation in (ROOT / ".github/workflows/cd.yml").read_text(encoding="utf-8")
