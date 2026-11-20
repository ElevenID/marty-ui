"""Standalone website authority cannot widen other web release roles."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ui_release as ui
import website_producer_policy as policy
import website_release as web


def standalone():
    return {"repository": policy.STANDALONE_REPOSITORY, "workflow": policy.STANDALONE_WORKFLOW,
            "ref": policy.REF, "source_sha": "a" * 40, "run_id": "123", "run_attempt": "2"}


def test_standalone_has_only_its_exact_website_authority():
    assert policy.producer_policy(policy.STANDALONE_REPOSITORY, role="website") == {
        "repository": "ElevenID/website", "repository_id": "1459542519",
        "workflow": ".github/workflows/production-website-release.yml", "ref": "refs/heads/main",
    }
    value = standalone()
    assert policy.validate_producer(value, role="website") is value
    assert policy.image_policy(policy.STANDALONE_IMAGE, role="website")["repository"] == policy.STANDALONE_REPOSITORY
    assert policy.STANDALONE_REPOSITORY not in web.REPOSITORIES
    assert web.REPOSITORIES == policy.LEGACY_REPOSITORIES


@pytest.mark.parametrize("role", ["application", "composition", "backend", "installer", "", None])
def test_standalone_cannot_produce_another_component_or_unknown_role(role):
    with pytest.raises(ValueError):
        policy.validate_producer(standalone(), role=role)
    with pytest.raises(ValueError):
        policy.image_policy(policy.STANDALONE_IMAGE, role=role)


@pytest.mark.parametrize("role", policy.ROLES)
@pytest.mark.parametrize("repository,workflow,identity", [
    (ui.REPOSITORY, ui.WORKFLOW, "1140864197"),
    (ui.COMMERCE_REPOSITORY, ui.COMMERCE_WORKFLOW, "1207411806"),
])
def test_legacy_producer_authority_is_preserved(role, repository, workflow, identity):
    selected = policy.producer_policy(repository, role=role)
    assert selected == {"repository": repository, "repository_id": identity, "workflow": workflow, "ref": policy.REF}
    value = {**standalone(), "repository": repository, "workflow": workflow}
    assert policy.validate_producer(value, role=role) == value


@pytest.mark.parametrize("field,value", [
    ("repository", ui.REPOSITORY), ("repository", "ElevenID/another-website"),
    ("workflow", ui.WORKFLOW), ("workflow", ui.COMMERCE_WORKFLOW),
    ("ref", "refs/pull/13/merge"), ("source_sha", "main"), ("source_sha", "A" * 40),
    ("run_id", "0"), ("run_attempt", "01"), ("run_attempt", 1),
    ("run_id", True), ("extra", "ignored"),
])
def test_standalone_producer_rejects_wrong_identity_types_and_extra_fields(field, value):
    changed = {**standalone(), field: value}
    with pytest.raises(ValueError):
        policy.validate_producer(changed, role="website")


@pytest.mark.parametrize("uri,role", [
    (ui.PUBLIC_IMAGE, "website"), (ui.COMMERCE_IMAGE, "website"),
    (policy.LEGACY_WEBSITE_IMAGE, "application"),
    (policy.LEGACY_COMMERCE_WEBSITE_IMAGE, "application"),
    (policy.LEGACY_WEBSITE_IMAGE, "composition"),
    (policy.STANDALONE_IMAGE + ":latest", "website"),
    (policy.STANDALONE_IMAGE + "@sha256:" + "a" * 64, "website"),
    ("ghcr.io/someone/website", "website"),
])
def test_image_roles_and_fixed_coordinates_cannot_be_substituted(uri, role):
    with pytest.raises(ValueError):
        policy.image_policy(uri, role=role)


def test_callers_cannot_mutate_a_returned_allowlist_to_expand_trust():
    selected = policy.repositories_for("website")
    selected["attacker/repo"] = "1"
    selected[ui.REPOSITORY] = "wrong"
    assert policy.repositories_for("website")[ui.REPOSITORY] == "1140864197"
    with pytest.raises(ValueError):
        policy.producer_policy("attacker/repo", role="website")
