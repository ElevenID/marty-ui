import copy
import hashlib

import pytest

from scripts.produce_passport_beta_demo_publication import (
    NEGATIVE,
    PublicationEvidenceError,
    expected_from_live_preliminary,
    stage_negative_media,
)

SOURCE = "a" * 40
HASHES = {
    name: character * 64
    for name, character in (
        ("stack_manifest_sha256", "b"),
        ("aggregate_deployment_receipt_sha256", "c"),
        ("aggregate_plan_sha256", "d"),
        ("production_snapshot_commitment", "e"),
        ("production_attachment_commitment", "f"),
    )
}
MEDIA = {
    "unsigned-callback-uncut.webm": "4" * 64,
    "unsigned-callback-privacy-scan.json": "5" * 64,
    "foreign-callback-uncut.webm": "6" * 64,
    "foreign-callback-privacy-scan.json": "7" * 64,
}


def fixtures():
    release = {
        "source_commit": SOURCE,
        "stack_manifest_sha256": HASHES["stack_manifest_sha256"],
        "signed_manifest_verified": True,
    }
    deployment = {
        name: HASHES[name] for name in HASHES if name != "stack_manifest_sha256"
    }
    live = {
        "schema": "marty.passport-beta-acceptance/v1",
        "status": "blocked",
        "beta_origin": "https://beta.elevenidllc.com",
        "physical_claim": "not_claimed",
        "release": release,
        "deployment": {**deployment, "provider_mode": "simulator"},
    }
    preliminary = {
        "kind": "preliminary",
        "run_id": 111,
        "workflow_commit": SOURCE,
        "artifact_sha256": "3" * 64,
        "media_sha256": MEDIA,
        "value": {
            "schema": "marty.passport-beta-preliminary/v1",
            "status": "qualified_for_recording",
            "beta_origin": "https://beta.elevenidllc.com",
            "physical_claim": "not_claimed",
            "synthetic_identities_only": True,
            "release": release,
            "deployment": {
                "provider_mode": "simulator",
                **{
                    name: deployment[name]
                    for name in (
                        "aggregate_deployment_receipt_sha256",
                        "aggregate_plan_sha256",
                    )
                },
            },
            "probes": {
                "nine_route_gateway_flow": {
                    "verified": True,
                    "evidence": {
                        "source_job_commitment": "1" * 64,
                        "bureau_job_commitment": "2" * 64,
                    },
                }
            },
        },
    }
    return live, preliminary


def test_expected_identity_matches_four_field_final_publication_join():
    live, preliminary = fixtures()
    expected = expected_from_live_preliminary(live, preliminary, SOURCE)
    assert expected["deployment"] == {
        name: live["deployment"][name]
        for name in HASHES
        if name != "stack_manifest_sha256"
    }
    assert expected["preliminary"] == {
        "run_id": 111,
        "artifact_sha256": "3" * 64,
        "negative_media_sha256": MEDIA,
    }
    assert expected["selected_source_job_commitment"] == "1" * 64


@pytest.mark.parametrize(
    "change",
    [
        lambda live, preliminary: live["release"].update(source_commit="0" * 40),
        lambda live, preliminary: live["deployment"].update(
            production_attachment_commitment="invalid"
        ),
        lambda live, preliminary: preliminary.update(workflow_commit="0" * 40),
        lambda live, preliminary: preliminary["value"]["deployment"].update(
            aggregate_plan_sha256="0" * 64
        ),
        lambda live, preliminary: preliminary["value"]["probes"][
            "nine_route_gateway_flow"
        ].update(verified=False),
        lambda live, preliminary: preliminary["media_sha256"].update(
            {"foreign-callback-uncut.webm": MEDIA["unsigned-callback-uncut.webm"]}
        ),
    ],
)
def test_expected_identity_rejects_stale_or_unverified_inputs(change):
    live, preliminary = copy.deepcopy(fixtures())
    change(live, preliminary)
    with pytest.raises(PublicationEvidenceError):
        expected_from_live_preliminary(live, preliminary, SOURCE)


def test_protected_negative_media_preserves_matching_reviewed_files(tmp_path):
    stage = tmp_path / "protected"
    video_dir = tmp_path / "reviewed"
    stage.mkdir()
    video_dir.mkdir()
    hashes = {}
    for name in NEGATIVE:
        raw = name.encode()
        (stage / name).write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    existing = video_dir / NEGATIVE[0]
    existing.write_bytes(NEGATIVE[0].encode())
    copied = []
    stage_negative_media(stage, video_dir, hashes, copied)
    assert existing not in copied
    assert len(copied) == 3
    assert all(path.read_bytes() == path.name.encode() for path in copied)
    existing.write_bytes(b"changed reviewed clip")
    with pytest.raises(PublicationEvidenceError, match="differs from the protected"):
        stage_negative_media(stage, video_dir, hashes, [])
