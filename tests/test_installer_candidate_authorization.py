"""Acceptance-only record contracts; no signatures or target execution are mocked as acceptance."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as release


@pytest.fixture
def candidate(tmp_path):
    assets = tmp_path / "assets"
    assets.mkdir()
    for name in release.ARTIFACTS:
        (assets / name).write_bytes(b"synthetic " + name.encode())
    (assets / "prepared-selfhost-images.json").write_bytes(release.encode(dict(
        schema="marty.selfhost-image-lock/v1", release="marty-ui@1.2.3",
        services={"gateway": "ghcr.io/elevenid/services@sha256:" + "a" * 64},
        openbao_didcomm_image="ghcr.io/elevenid/plugin@sha256:" + "b" * 64)))
    producer = dict(source_sha="a" * 40, release_tag="v1.2.3", build_run_id=42, build_run_attempt=2)
    inventory = release.encode(release.inventory(assets, expected_services={"gateway"}, **producer))
    run = dict(repository=dict(full_name=release.REPOSITORY), path=release.acceptance.WORKFLOW,
               head_sha="c" * 40, head_branch="main", event="workflow_dispatch", status="in_progress",
               conclusion=None, id=99, run_attempt=3)
    return inventory, dict(**producer, acceptance_run=run, phase="staged", now=100000)


def context(record):
    return {key: record[key] for key in ("source_sha", "release_tag", "operator_sha256", "phase",
                                       "nonce", "harness_source_sha", "run_id", "run_attempt")}


@pytest.mark.parametrize("phase", ["staged", "published"])
def test_authorization_is_short_lived_separate_from_admission(candidate, phase):
    inventory, options = candidate
    options["phase"] = phase
    record = release.candidate_authorization(inventory, **options)
    other = release.candidate_authorization(inventory, **options)
    assert record["nonce"] != other["nonce"]
    assert record["scope"] == "acceptance-only" and "status" not in record
    assert record["expires_at"] - record["issued_at"] == 3600
    raw = release.encode(record)
    assert release.bind_candidate_authorization(raw, inventory, expected=context(record), now=100000)[0] == record
    for now in (99999, 103600):
        with pytest.raises(ValueError):
            release.bind_candidate_authorization(raw, inventory, expected=context(record), now=now)
    release.bind_candidate_authorization(raw, inventory, expected=context(record), now=103599)
    with pytest.raises(ValueError):
        release.validate_admission(record)
    with pytest.raises(ValueError):
        release.validate_channel(record, now=100000)


@pytest.mark.parametrize("field,value", [
    ("schema", "elevenid.installer-admission/v1"), ("scope", "accepted"),
    ("source_ref", "refs/heads/feature"), ("repository", "Other/repo"),
    ("platform", "linux/arm64"), ("workflow", release.PROMOTION_WORKFLOW),
    ("phase", "channel"), ("phase", {}), ("nonce", "0"), ("harness_source_sha", "abc"),
    ("issued_at", 100001), ("expires_at", 103601), ("expires_at", 100000),
    ("run_id", True), ("run_attempt", 0), ("build_run_attempt", False),
    ("build_run_id", 2**53), ("extra", True),
])
def test_closed_authorization_schema_refuses_invalid_values(candidate, field, value):
    inventory, options = candidate
    record = release.candidate_authorization(inventory, **options)
    record[field] = value
    with pytest.raises(ValueError):
        release.validate_candidate_authorization(record, now=100000)


@pytest.mark.parametrize("field,value", [
    ("source_sha", "b" * 40), ("release_tag", "v1.2.4"), ("operator_sha256", "b" * 64),
    ("phase", "published"), ("nonce", "e" * 64), ("harness_source_sha", "d" * 40),
    ("run_id", 100), ("run_attempt", 4),
])
def test_expected_context_is_independent(candidate, field, value):
    inventory, options = candidate
    record = release.candidate_authorization(inventory, **options)
    expected = context(record)
    expected[field] = value
    with pytest.raises(ValueError, match="context"):
        release.bind_candidate_authorization(release.encode(record), inventory, expected=expected, now=100000)


@pytest.mark.parametrize("field,value", [
    ("path", release.PROMOTION_WORKFLOW), ("head_branch", "feature"),
    ("head_sha", "bad"), ("status", "completed"), ("event", "pull_request"),
    ("conclusion", "success"), ("id", True), ("run_attempt", 0),
    ("repository", dict(full_name="Other/repo")),
])
def test_issuance_requires_independent_active_acceptance_run(candidate, field, value):
    inventory, options = candidate
    options["acceptance_run"][field] = value
    with pytest.raises(ValueError):
        release.candidate_authorization(inventory, **options)


def test_inventory_bytes_and_producer_cannot_change(candidate):
    inventory, options = candidate
    record = release.candidate_authorization(inventory, **options)
    for changed in (inventory + b" ", inventory.replace(b'"build_run_attempt":2', b'"build_run_attempt":4')):
        with pytest.raises(ValueError):
            release.bind_candidate_authorization(release.encode(record), changed, expected=context(record), now=100000)
    bad = copy.deepcopy(options)
    bad["build_run_attempt"] = 4
    with pytest.raises(ValueError):
        release.candidate_authorization(inventory, **bad)
    raw = release.encode(record)
    duplicate = raw.replace(b'"scope":"acceptance-only"', b'"scope":"acceptance-only","scope":"accepted"')
    for invalid in (duplicate, b" " * 65537, b"{}"):
        with pytest.raises(ValueError):
            release.bind_candidate_authorization(invalid, inventory, expected=context(record), now=100000)


def test_shared_native_candidate_fixture():
    path = Path(__file__).resolve().parents[1] / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json"
    fixture = json.loads(path.read_text())
    authorization, inventory = fixture["authorization"].encode(), fixture["inventory"].encode()
    expected = context(release.decode(authorization))
    assert release.bind_candidate_authorization(authorization, inventory, expected=expected, now=fixture["now"])
    zero_epoch = release.decode(authorization)
    zero_epoch.update(issued_at=0, expires_at=3600)
    for now in (0, 1):
        with pytest.raises(ValueError):
            release.validate_candidate_authorization(zero_epoch, now=now)
