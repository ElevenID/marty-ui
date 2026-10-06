import copy
import hashlib
import json

import pytest

from scripts import compose_passport_beta_final_acceptance as final
from scripts.collect_passport_beta_acceptance import REQUIRED_PROBES

SOURCE = "a" * 40


def fixture(monkeypatch):
    lineage = {
        "release": {"source_commit": SOURCE, "stack_manifest_sha256": "b" * 64},
        "deployment": {
            "production_snapshot_commitment": "c" * 64,
            "production_attachment_commitment": "d" * 64,
        },
    }
    monkeypatch.setattr(final, "match_preliminary_soak", lambda *_: lineage)
    monkeypatch.setattr(
        final,
        "match_publication",
        lambda *_: {
            "verified": True,
            "evidence": {"video_id": "abcdefghijk"},
        },
    )
    prior = {
        name: {"verified": True, "evidence": {"commitment": "f" * 64}}
        for name in REQUIRED_PROBES
        if name
        not in (
            "packaged_image",
            "legacy_drain",
            "production_isolation",
            "recorded_demo",
        )
    }
    live = {
        "release": {**lineage["release"], "signed_manifest_verified": True},
        "deployment": lineage["deployment"],
        "runtime_images": {
            "passport-beta-bureau": {
                "container_id": "e" * 64,
                "oci_digest": "sha256:" + "1" * 64,
                "oci_reference": "ghcr.io/elevenid/services@sha256:" + "1" * 64,
            }
        },
        "probes": {
            "capabilities_http": {"verified": True},
            "unauthenticated_denial": {"verified": True},
        },
    }
    preliminary = {
        "run_id": 111,
        "artifact_sha256": "2" * 64,
        "value": {"probes": prior},
    }
    soak = {
        "sample_count": 3,
        "minimum_hours": 24,
        "identity": {
            "simulator_container_id": "e" * 64,
            "simulator_oci_digest": "sha256:" + "1" * 64,
        },
        "samples": [{"run_id": str(run)} for run in (222, 223, 224)],
        "first_observed_at_utc": "2026-10-01T12:00:00+00:00",
        "last_observed_at_utc": "2026-10-02T12:00:00+00:00",
    }
    publication = {"run_id": 333, "artifact_sha256": "3" * 64}
    return live, preliminary, soak, publication


def test_final_acceptance_keeps_only_reviewed_probe_and_lineage_evidence(monkeypatch):
    live, preliminary, soak, publication = fixture(monkeypatch)
    report = final.compose(
        live,
        preliminary,
        soak,
        publication,
        copy.deepcopy(final.EXPECTED_DRAIN),
        {"verified": True},
        SOURCE,
        444,
        fresh_selected=True,
        fresh_public={
            "verified": True,
            "video_id": "abcdefghijk",
            "checked_at_utc": "2026-10-02T12:05:00+00:00",
            "page_verified": True,
        },
    )
    assert report["status"] == "accepted"
    assert all(report["probes"][name]["verified"] for name in REQUIRED_PROBES)
    assert report["probes"]["recorded_demo"]["evidence"]["video_id"] == "abcdefghijk"
    assert report["lineage"]["publication_run_id"] == 333
    assert report["booklet_verified"] is False


def test_final_acceptance_rejects_runtime_drift_or_missing_preliminary_probe(
    monkeypatch,
):
    live, preliminary, soak, publication = fixture(monkeypatch)
    drifted = copy.deepcopy(soak)
    drifted["identity"]["simulator_container_id"] = "0" * 64
    with pytest.raises(final.FinalAcceptanceError, match="runtime differs"):
        final.compose(
            live,
            preliminary,
            drifted,
            publication,
            copy.deepcopy(final.EXPECTED_DRAIN),
            {"verified": True},
            SOURCE,
            444,
            fresh_selected=True,
            fresh_public={
                "verified": True,
                "video_id": "abcdefghijk",
                "checked_at_utc": "2026-10-02T12:05:00+00:00",
                "page_verified": True,
            },
        )
    missing = copy.deepcopy(preliminary)
    del missing["value"]["probes"]["managed_csca_dsc_chain"]
    with pytest.raises(final.FinalAcceptanceError, match="probe set is incomplete"):
        final.compose(
            live,
            missing,
            soak,
            publication,
            copy.deepcopy(final.EXPECTED_DRAIN),
            {"verified": True},
            SOURCE,
            444,
            fresh_selected=True,
            fresh_public={
                "verified": True,
                "video_id": "abcdefghijk",
                "checked_at_utc": "2026-10-02T12:05:00+00:00",
                "page_verified": True,
            },
        )


def test_final_acceptance_rejects_stale_publication_after_soak(monkeypatch):
    live, preliminary, soak, publication = fixture(monkeypatch)
    with pytest.raises(final.FinalAcceptanceError, match="not rechecked after soak"):
        final.compose(
            live,
            preliminary,
            soak,
            publication,
            copy.deepcopy(final.EXPECTED_DRAIN),
            {"verified": True},
            SOURCE,
            444,
            fresh_selected=True,
            fresh_public={
                "verified": True,
                "video_id": "abcdefghijk",
                "checked_at_utc": "2026-10-01T12:05:00+00:00",
                "page_verified": True,
            },
        )


def test_final_live_selected_job_must_remain_active_and_commitment_bound(monkeypatch):
    lineage = {
        "release": {"source_commit": SOURCE, "stack_manifest_sha256": "b" * 64},
        "selected_source_job_commitment": "1" * 64,
        "selected_bureau_job_commitment": "2" * 64,
    }
    handoff = {
        "source_commit": SOURCE,
        "stack_manifest_sha256": "b" * 64,
        "source_job_id": "job-1",
        "bureau_job_id": "bureau-1",
        "application_id": "app-1",
        "organization_id": "org-1",
    }
    status = {
        "id": "job-1",
        "bureau_job_id": "bureau-1",
        "application_id": "app-1",
        "organization_id": "org-1",
        "status": "ACTIVE",
    }
    monkeypatch.setattr(final, "request_beta", lambda *_: (200, status))
    monkeypatch.setattr(
        final,
        "_identity_commit",
        lambda _, label, __: ("1" if label == "source-job" else "2") * 64,
    )
    final.recheck_selected_job(handoff, lineage, "a" * 32)
    status["status"] = "FAILED"
    with pytest.raises(final.FinalAcceptanceError, match="no longer ACTIVE"):
        final.recheck_selected_job(handoff, lineage, "a" * 32)


def test_final_public_demo_requires_current_manifest_video_and_page(monkeypatch):
    manifest = {
        "scenarios": [
            {
                "slug": final.SLUG,
                "state": "PUBLIC",
                "youtube_id": "abcdefghijk",
                "title": "Physical passport issuance evidence",
            }
        ]
    }
    raw_manifest = json.dumps(manifest).encode()
    publication = {
        "value": {
            "youtube": {"video_id": "abcdefghijk"},
            "media": {
                "public_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest()
            },
        }
    }
    calls = []

    def fetch(url, _):
        calls.append(url)
        return (
            raw_manifest
            if url == final.DEMO_MANIFEST
            else b"<html>demo</html>"
        )

    monkeypatch.setattr(final, "public_get", fetch)
    final.recheck_public_demo(publication)
    assert calls == [final.DEMO_MANIFEST, final.DEMO_PAGE]
    assert final.DEMO_MANIFEST.startswith("https://beta.elevenidllc.com/")
    assert final.DEMO_PAGE.startswith("https://beta.elevenidllc.com/")
    publication["value"]["media"]["public_manifest_sha256"] = "0" * 64
    with pytest.raises(final.FinalAcceptanceError, match="reviewed publication bytes"):
        final.recheck_public_demo(publication)
    publication["value"]["media"]["public_manifest_sha256"] = hashlib.sha256(
        raw_manifest
    ).hexdigest()
    manifest["scenarios"][0]["state"] = "DRAFT"
    raw_manifest = json.dumps(manifest).encode()
    publication["value"]["media"]["public_manifest_sha256"] = hashlib.sha256(
        raw_manifest
    ).hexdigest()
    with pytest.raises(final.FinalAcceptanceError, match="no longer names"):
        final.recheck_public_demo(publication)
