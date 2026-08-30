from __future__ import annotations

import json

from scripts.create_demo_manifest_draft import (
    CONTRACT_PATH,
    POSTER_PATH,
    build_manifest,
)
from scripts.demo_asset_hashes import public_asset_sha256
from scripts.validate_demo_manifests import validate_manifest


def test_draft_is_complete_unbound_and_generated_from_the_reviewed_contract() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    manifest = build_manifest()
    scenario_count = len(contract["scenarios"])

    validate_manifest(manifest)
    assert manifest["binding_state"] == "PENDING_DEPLOYMENT"
    assert manifest["deployment_release_marker"] is None
    assert manifest["component_revisions"] == []
    assert manifest["image_digests"] == []
    assert manifest["release_evidence"]["source_marker"] is None
    assert [item["slug"] for item in manifest["scenarios"][:scenario_count]] == [
        item["slug"] for item in contract["scenarios"]
    ]
    assert [item["slug"] for item in manifest["scenarios"][scenario_count:]] == (
        contract["preserved_legacy_scenarios"]
    )
    poster_hash = public_asset_sha256(POSTER_PATH)
    assert all(
        item["poster"]["sha256"] == poster_hash for item in manifest["scenarios"]
    )


def test_every_behavioral_path_has_an_explicit_not_run_assertion() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    for scenario in build_manifest()["scenarios"][: len(contract["scenarios"])]:
        plan = scenario["recording_plan"]
        assertion_results = {
            item["id"]: item["result"] for item in scenario["assertions"]
        }
        paths = plan["happy_path"] + plan["failure_paths"]
        assert assertion_results == {path: "NOT_RUN" for path in paths}


def test_external_admissions_draft_uses_the_public_webhook_protocol() -> None:
    scenario = next(
        item
        for item in build_manifest()["scenarios"]
        if item["slug"] == "external-admissions-gateway-webhooks"
    )

    assert scenario["demo_id"] == "D-11"
    assert scenario["protocols"] == ["https-webhooks"]
    assert scenario["audiences"] == [
        "Integration developer",
        "Security architect",
        "Identity product buyer",
    ]
    assert len(scenario["transcript"]["segments"]) == 4
    assert {item["id"] for item in scenario["assertions"]} == {
        "gateway_only_summary",
        "scoped_approval",
        "signed_webhook_correlated",
        "insufficient_scope_denied",
        "invalid_signature_rejected",
        "duplicate_event_ignored",
    }
