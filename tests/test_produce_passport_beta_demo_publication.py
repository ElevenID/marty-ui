import copy
import hashlib
import json

import pytest

from scripts.produce_passport_beta_demo_publication import (
    NEGATIVE,
    PublicationEvidenceError,
    expected_from_live_preliminary,
    require_beta_deploy_config,
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


def test_protected_publisher_requires_beta_only_deploy_and_rollback(tmp_path):
    script = "scripts/deploy-passport-demo-content-beta.ps1"
    config = {
        "automation": {
            name: {
                "command": "powershell.exe",
                "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                         script, "-Mode", mode],
                "cwd": ".",
            }
            for name, mode in (("deploy", "Deploy"), ("rollbackDeploy", "Rollback"))
        }
    }
    config["automation"]["record"] = {
        "command": "node", "args": ["-e", "process.exit(1)"], "cwd": ".",
    }
    config["automation"]["prePublicBuild"] = {
        "command": "node", "args": ["-e", "process.exit(0)"], "cwd": ".",
    }
    config["automation"]["smoke"] = {
        "command": "node",
        "args": ["tests/scripts/smoke-beta-demo-publication.js"],
        "cwd": ".",
    }
    path = tmp_path / "reviewed.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    require_beta_deploy_config(path)
    for name, field, value in (
        ("deploy", "args", ["-File", "scripts/deploy-demo-content.ps1"]),
        ("rollbackDeploy", "args", ["-File", "scripts/deploy-demo-content.ps1"]),
        ("deploy", "cwd", "../unreviewed-checkout"),
        ("deploy", "command", "bash"),
    ):
        changed = copy.deepcopy(config)
        changed["automation"][name][field] = value
        path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(PublicationEvidenceError, match="beta-only"):
            require_beta_deploy_config(path)
    changed = copy.deepcopy(config)
    del changed["automation"]["rollbackDeploy"]
    path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(PublicationEvidenceError, match="missing or unrestricted"):
        require_beta_deploy_config(path)
    for name in ("record", "prePublicBuild"):
        changed = copy.deepcopy(config)
        changed["automation"][name] = {
            "command": "powershell.exe",
            "args": ["-File", "scripts/deploy-demo-content.ps1"],
        }
        path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(PublicationEvidenceError, match="hook"):
            require_beta_deploy_config(path)
    changed = copy.deepcopy(config)
    changed["automation"]["smoke"]["args"] = ["unreviewed.js"]
    path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(PublicationEvidenceError, match="beta-only browser"):
        require_beta_deploy_config(path)


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
