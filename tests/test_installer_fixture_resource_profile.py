"""Closed resource/seed policy only; no host, guest or daemon mutation."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_policy as policy
import installer_candidate_vm_seed as seed


def fixture_seed():
    return dict(schema=policy.seed_schema(policy.ROOTLESS_FIXTURE_RESOURCE_PROFILE),
                guest_user=policy.GUEST_USER, packages=dict(policy.PACKAGES),
                **policy.profile_seed_fields(policy.ROOTLESS_FIXTURE_RESOURCE_PROFILE))


def test_fixture_has_explicit_two_gib_schema_without_changing_existing_profiles():
    profile = policy.ROOTLESS_FIXTURE_RESOURCE_PROFILE
    assert profile not in policy.ROOTLESS_PROFILES
    assert policy.memory_mib(None) == 4096
    assert all(policy.memory_mib(value) == 8192 for value in policy.ROOTLESS_PROFILES)
    assert policy.memory_mib(profile) == 2048
    assert policy.seed_profile(fixture_seed()) == profile
    assert policy.seed_schema(profile).endswith("/v3")
    assert policy.launch_schema(profile).endswith("/v3")
    assert policy.seed_schema(None).endswith("/v1")
    assert all(policy.seed_schema(value).endswith("/v2") for value in policy.ROOTLESS_PROFILES)


@pytest.mark.parametrize("field,value", [
    ("schema", "elevenid.installer-vm-seed/v1"),
    ("schema", "elevenid.installer-vm-seed/v2"),
    ("resource_profile", policy.ROOTLESS_STARTUP_PROFILE),
    ("guest_uid", 0), ("guest_uid", True),
    ("fixture_profile", "invented"), ("bootstrap_engine", "product-rootless-ready"),
    ("packages", {}), ("docker_host", policy.ROOTLESS_DOCKER_HOST),
    ("rootless_assets_sha256", policy.ROOTLESS_ASSETS_SHA256),
])
def test_fixture_rejects_downgrades_profile_mixups_and_daemon_authority(field, value):
    record = deepcopy(fixture_seed())
    record[field] = value
    with pytest.raises(ValueError):
        policy.seed_profile(record)


def test_rendered_fixture_separates_installer_from_setup_admin_and_pins_uid():
    public = "ssh-ed25519 " + "A" * 44
    private = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 120 + "\n-----END OPENSSH PRIVATE KEY-----\n"
    raw = seed._cloud_config(public, public, private,
                             resource_profile=policy.ROOTLESS_FIXTURE_RESOURCE_PROFILE)
    installer = raw.split(b"  - name: installer\n", 1)[1].split(b"  - name: fixture-admin\n", 1)[0]
    assert f"uid: {policy.ROOTLESS_UID}".encode() in installer
    assert b"sudo: false" in installer and b"NOPASSWD" not in installer
    assert b"groups: docker" not in installer
    assert b"fixture-admin" in raw and b"enable, --now, docker" in raw
    assert b"dockerd-rootless-setuptool.sh" not in raw


@pytest.mark.parametrize("profile", [2048, True, "installer_only_rootless_fixture", "invented"])
def test_numeric_or_legacy_tags_cannot_select_a_resource_profile(profile):
    with pytest.raises(ValueError):
        policy.memory_mib(profile)
