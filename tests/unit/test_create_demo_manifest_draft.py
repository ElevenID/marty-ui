from __future__ import annotations

import hashlib
import json

from scripts.create_demo_manifest_draft import (
    CONTRACT_PATH,
    POSTER_PATH,
    build_manifest,
)
from scripts.validate_demo_manifests import validate_manifest


def test_draft_is_complete_unbound_and_generated_from_the_reviewed_contract() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    manifest = build_manifest()

    validate_manifest(manifest)
    assert manifest["binding_state"] == "PENDING_DEPLOYMENT"
    assert manifest["deployment_release_marker"] is None
    assert manifest["component_revisions"] == []
    assert manifest["image_digests"] == []
    assert manifest["release_evidence"]["source_marker"] is None
    assert [item["slug"] for item in manifest["scenarios"][:10]] == [
        item["slug"] for item in contract["scenarios"]
    ]
    assert [item["slug"] for item in manifest["scenarios"][10:]] == contract[
        "preserved_legacy_scenarios"
    ]
    poster_hash = hashlib.sha256(POSTER_PATH.read_bytes()).hexdigest()
    assert all(
        item["poster"]["sha256"] == poster_hash for item in manifest["scenarios"]
    )


def test_every_behavioral_path_has_an_explicit_not_run_assertion() -> None:
    for scenario in build_manifest()["scenarios"][:10]:
        plan = scenario["recording_plan"]
        assertion_results = {
            item["id"]: item["result"] for item in scenario["assertions"]
        }
        paths = plan["happy_path"] + plan["failure_paths"]
        assert assertion_results == {path: "NOT_RUN" for path in paths}
