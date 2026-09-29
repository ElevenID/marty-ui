"""Candidate approval must bind signed baseline, live beta, and deletion head."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.prepare_passport_beta_fence_approval import prepare
from scripts.probe_passport_beta_host import HostProbeError


UI_HEAD = "a" * 40
DELETION_HEAD = "b" * 40
ISSUANCE = "ghcr.io/elevenid/issuance@sha256:" + "c" * 64
SERVICES = "ghcr.io/elevenid/services@sha256:" + "d" * 64
UI = "ghcr.io/elevenid/ui@sha256:" + "1" * 64


def fixture(tmp_path: Path):
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(json.dumps({"components": [{
        "name": "marty-ui", "repository": "ElevenID/marty-ui",
        "commit": UI_HEAD,
    }]}), encoding="utf-8")
    target = {
        "schema": "marty.passport-beta-fence-target/v1",
        "authority": "discovery_only_requires_protected_baseline",
        "observation_sha256": "e" * 64,
        "production_attachments_sha256": "f" * 64,
        "beta": {
            "postgres_system_identifier": "12345", "database_oid": "87774",
            "ui_project": "elevenid-beta-ui",
            "ui_service": {"configured_image": UI},
            "services": {
                "issuance": {"configured_image": ISSUANCE},
                **{name: {"configured_image": SERVICES} for name in
                   ("gateway", "flow", "issuance-native", "signing-keys")},
            },
        },
    }
    signed = {
        "source_commit": UI_HEAD, "issuance_image": ISSUANCE,
        "ui_image": UI,
        "services_image": SERVICES,
    }
    deletion = {"state": "OPEN", "isDraft": True,
                "headRefOid": DELETION_HEAD}
    return manifest, target, signed, deletion


def test_prepare_binds_signed_live_target_and_deletion(tmp_path: Path) -> None:
    manifest, target, signed, deletion = fixture(tmp_path)
    result = prepare(
        manifest, observer=lambda: target,
        runner=lambda _: json.dumps(deletion),
        source=lambda path, head: signed if (path, head) == (manifest, UI_HEAD)
            else pytest.fail("Wrong signed baseline source"),
    )
    assert result["credentials_deletion_head"] == DELETION_HEAD
    assert result["observation_sha256"] == "e" * 64
    assert result["beta_baseline_source_commit"] == UI_HEAD


@pytest.mark.parametrize("change", [
    lambda target: target["beta"]["services"]["issuance"].update(
        configured_image="unreviewed-image"),
    lambda target: target["beta"]["services"].update(gateway=None),
    lambda target: target["beta"]["ui_service"].update(
        configured_image="unreviewed-ui"),
    lambda target: target["beta"].update(database_oid=None),
    lambda target: target.update(beta=None),
    lambda target: target.update(observation_sha256="bad"),
])
def test_prepare_rejects_changed_or_invalid_live_target(
    tmp_path: Path, change,
) -> None:
    manifest, target, signed, deletion = fixture(tmp_path)
    change(target)
    with pytest.raises(HostProbeError):
        prepare(manifest, observer=lambda: target,
                runner=lambda _: json.dumps(deletion), source=lambda *_: signed)


@pytest.mark.parametrize("change", [
    lambda deletion: deletion.update(headRefOid="not-a-commit"),
    lambda deletion: deletion.update(isDraft=False),
    lambda deletion: deletion.update(state="MERGED"),
])
def test_prepare_rejects_changed_deletion_head(
    tmp_path: Path, change,
) -> None:
    manifest, target, signed, deletion = fixture(tmp_path)
    change(deletion)
    with pytest.raises(HostProbeError, match="Python deletion PR"):
        prepare(manifest, observer=lambda: target,
                runner=lambda _: json.dumps(deletion), source=lambda *_: signed)
