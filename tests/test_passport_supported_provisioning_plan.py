"""Signed release and protected plan provenance must precede Docker inspection."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from scripts.passport_supported_provisioning_plan import (
    PlanError, build_plan, protected_context, release_inputs, verify_record,
)


SOURCE = "a" * 40
LEGACY_SOURCE = "b" * 40
NOW = datetime(2026, 9, 27, 13, tzinfo=timezone.utc)
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "c" * 64
MIGRATIONS = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "d" * 64
LEGACY = "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "e" * 64


def manifest() -> dict:
    return {"schema": "marty.stack/v1", "components": [
        {"name": "marty-ui", "repository": "ElevenID/marty-ui",
         "version": "1.1.218", "commit": SOURCE,
         "artifacts": [
             {"type": "oci", "uri": "ghcr.io/elevenid/marty-ui-oss/services",
              "digest": "sha256:" + "c" * 64},
             {"type": "oci", "uri": "ghcr.io/elevenid/marty-ui-oss/migrations",
              "digest": "sha256:" + "d" * 64},
             {"type": "oci", "uri": "ghcr.io/elevenid/marty-ui-oss/ui",
              "digest": "sha256:" + "f" * 64},
         ]},
        {"name": "marty-credentials-issuance",
         "repository": "ElevenID/marty-credentials", "version": "0.1.78",
         "commit": LEGACY_SOURCE, "artifacts": [
             {"type": "oci", "uri": "ghcr.io/elevenid/marty-credentials-issuance",
              "digest": "sha256:" + "e" * 64},
         ]},
    ]}


def verified_inputs(tmp_path: Path) -> dict:
    path = tmp_path / "stack-manifest.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    attested = []
    def attest(*args) -> bool:
        attested.append(args)
        return True
    result = release_inputs(path, SOURCE, verify_ui=lambda *args: True,
                            attest=attest)
    assert result["services_reference"] == SERVICES
    assert result["migrations_reference"] == MIGRATIONS
    assert result["legacy_reference"] == LEGACY
    assert attested == [(
        "oci://" + LEGACY, "ElevenID/marty-credentials",
        "ElevenID/marty-credentials/.github/workflows/release-images.yml",
        LEGACY_SOURCE, "refs/tags/v0.1.78")]
    return result


def test_plan_derives_exact_disposable_identity_and_short_lease(tmp_path: Path) -> None:
    plan = build_plan("base", "123456789", verified_inputs(tmp_path),
                      NOW, "0123456789abcdef")
    assert plan["status"] == "blocked"
    assert plan["project"] == "marty-passport-acceptance-base-123456789012345"
    assert plan["owner_labels"]["com.marty.passport.acceptance.run-id"] == "123456789"
    assert plan["owner_labels"]["com.marty.passport.acceptance.services-image"] == SERVICES
    assert plan["expires_at"] == "2026-09-27T15:00:00+00:00"


def test_protected_workflow_context_excludes_aliases_and_other_branches() -> None:
    context = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ElevenID/marty-ui",
        "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": (
            "ElevenID/marty-ui/.github/workflows/"
            "passport-supported-provisioning-plan.yml@refs/heads/main"),
        "GITHUB_SHA": SOURCE, "GITHUB_RUN_ID": "123456789",
    }
    assert protected_context(context) == (SOURCE, "123456789")
    for key, value in (("GITHUB_REPOSITORY", "ElevenID/marty-ui-fork"),
                       ("GITHUB_REF", "refs/heads/production"),
                       ("GITHUB_WORKFLOW_REF", "other/workflow@refs/heads/main"),
                       ("GITHUB_WORKFLOW_REF", context["GITHUB_WORKFLOW_REF"] + "-evil"),
                       ("GITHUB_RUN_ID", "0")):
        bad = {**context, key: value}
        with pytest.raises(PlanError):
            protected_context(bad)


def test_release_rejects_unbound_credentials_image(tmp_path: Path) -> None:
    value = manifest()
    value["components"][1]["artifacts"][0]["uri"] = "ghcr.io/other/issuance"
    path = tmp_path / "stack-manifest.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PlanError, match="image"):
        release_inputs(path, SOURCE, verify_ui=lambda *args: True,
                       attest=lambda *args: True)
    value = manifest()
    value["components"][0]["commit"] = "f" * 40
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PlanError, match="protected main"):
        release_inputs(path, SOURCE, verify_ui=lambda *args: True,
                       attest=lambda *args: True)
    value = manifest()
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PlanError, match="attestation"):
        release_inputs(path, SOURCE, verify_ui=lambda *args: True,
                       attest=lambda *args: False)


def record_files(tmp_path: Path) -> tuple[Path, Path, dict, dict]:
    plan = build_plan("base", "123456789", verified_inputs(tmp_path),
                      NOW, "0123456789abcdef")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    record = {
        "schema": "marty.passport-supported-compose-ownership/v1",
        "plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        **{key: plan[key] for key in (
            "run_id", "project", "source_commit", "services_reference",
            "migrations_reference", "legacy_reference", "created_at",
            "expires_at", "owner_labels")},
        "containers": {}, "networks": {}, "volumes": [],
    }
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    return plan_path, record_path, plan, record


def test_unsigned_record_never_reaches_docker(tmp_path: Path) -> None:
    plan_path, record_path, _, _ = record_files(tmp_path)
    called = []
    with pytest.raises(PlanError, match="attestation"):
        verify_record(plan_path, record_path, NOW,
                      attest=lambda *args: False,
                      ownership=lambda *args: called.append(args))
    assert called == []


@pytest.mark.parametrize("key,value", [
    ("run_id", "777777777"),
    ("project", "marty-selfhost-prod"),
    ("services_reference", "ghcr.io/other/services@sha256:" + "c" * 64),
    ("legacy_reference", "ghcr.io/other/issuance@sha256:" + "e" * 64),
    ("migrations_reference", "ghcr.io/other/migrations@sha256:" + "d" * 64),
    ("plan_sha256", "0" * 64),
])
def test_attested_but_mismatched_record_never_reaches_docker(
    tmp_path: Path, key: str, value: str,
) -> None:
    plan_path, record_path, _, record = record_files(tmp_path)
    record[key] = value
    record_path.write_text(json.dumps(record), encoding="utf-8")
    called = []
    with pytest.raises(PlanError, match="differs from attested plan"):
        verify_record(plan_path, record_path, NOW,
                      attest=lambda *args: True,
                      ownership=lambda *args: called.append(args))
    assert called == []


def test_verified_plan_and_record_still_cannot_accept_rollback(tmp_path: Path) -> None:
    plan_path, record_path, _, record = record_files(tmp_path)
    attested = []
    def attest(*args) -> bool:
        attested.append(args)
        return True
    def ownership(*args) -> dict:
        assert args == (record, "base", NOW)
        return {"live_ownership_verified": True, "rollback_accepted": False}
    result = verify_record(plan_path, record_path, NOW,
                           attest=attest, ownership=ownership)
    assert result["status"] == "blocked"
    assert result["rollback_accepted"] is False
    assert [entry[2] for entry in attested] == [
        "ElevenID/marty-ui/.github/workflows/passport-supported-provisioning-plan.yml",
        "ElevenID/marty-ui/.github/workflows/passport-supported-provisioning-record.yml",
    ]
