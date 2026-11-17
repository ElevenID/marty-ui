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


def test_digital_passport_demo_waits_for_a_pinned_beta_protocol_release() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    candidate = contract["candidate_scenarios"]
    manifest = build_manifest()

    assert len(candidate) == 1
    assert candidate[0]["demo_id"] == "D-13"
    assert candidate[0]["slug"] == "passport-digital-handoff-evidence"
    assert candidate[0]["required_mip_version"] == "0.6.0-beta.1"
    assert candidate[0]["happy_path"] == [
        "managed_kms_csca_dsc_chain",
        "eight_step_digital_handoff_flow",
        "exact_package_cryptography_verified",
        "encrypted_handoff_tenant_bound",
        "independent_digital_quality_review",
    ]
    assert candidate[0]["failure_paths"] == ["foreign_or_tampered_package_denied"]
    assert manifest["mip_version"] == "0.5.0"
    assert "passport-digital-handoff-evidence" not in {
        scenario["slug"] for scenario in manifest["scenarios"]
    }


def test_passport_simulator_draft_matches_recorder_evidence_boundary() -> None:
    scenario = next(
        item
        for item in build_manifest()["scenarios"]
        if item["slug"] == "physical-passport-issuance-evidence"
    )

    assert scenario["demo_id"] == "D-12"
    assert scenario["state"] == "DRAFT"
    assert scenario["youtube_id"] is None
    assert scenario["media_evidence"] is None
    assert scenario["protocols"] == ["https-webhooks"]
    assert scenario["recording_plan"]["happy_path"] == [
        "managed_csca_dsc_issuer_profiles",
        "nine_step_passport_issuance_flow",
        "simulator_bureau_job_correlated",
        "signed_simulator_callback_verified",
        "physical_claim_boundary_verified",
        "physical_booklet_not_verified",
    ]
    assert scenario["recording_plan"]["failure_paths"] == [
        "unsigned_or_foreign_callback_denied",
    ]
    assert all(item["result"] == "NOT_RUN" for item in scenario["assertions"])
    assert any("Physical claim: not claimed" in segment["text"]
               for segment in scenario["transcript"]["segments"])
    assert any("no booklet" in limitation.lower()
               for limitation in scenario["limitations"])


def test_current_draft_retires_provider_demo_without_rewriting_archives():
    from scripts import create_demo_manifest_draft as generator
    from scripts.validate_demo_manifests import load_manifests
    manifest = generator.build_manifest()
    assert manifest["stack_version"] == "2026.08.1"
    assert all(item.get("demo_id") != "D-07" and "lti-1.3" not in item["protocols"]
               for item in manifest["scenarios"])
    assert "canvas" not in json.dumps(manifest).lower()
    index, archives = load_manifests(generator.ROOT / "ui/public/demos/manifests", generator.ROOT / "VERSION")
    assert index["latest_available_stack_version"] == "2026.08.0"
    assert any(item["slug"] == "canvas-learning-achievement" for item in archives["2026.08.0"]["scenarios"])


def test_generator_refuses_to_overwrite_an_existing_edition(tmp_path, monkeypatch):
    import pytest
    from scripts import create_demo_manifest_draft as generator
    target = tmp_path / "2026.08.0.json"
    target.write_text("immutable existing edition")
    monkeypatch.setattr(generator, "OUTPUT_PATH", target)
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        generator.main()
    assert target.read_text() == "immutable existing edition"
