"""Disposable Keycloak inputs stay scoped, source-backed, and fail closed."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from provision_selfhost_keycloak_kms import OUTPUTS, require_mounts, write_outputs  # noqa: E402
from with_disposable_event_stream_kms import PLUGIN_IMAGE  # noqa: E402


EXPECTED = {
    "keycloak_signing_kms_token", "keycloak_master_rs256_cert",
    "keycloak_11id_rs256_cert", "keycloak_master_cookie_token",
    "keycloak_master_ciba_token", "keycloak_11id_cookie_token",
    "keycloak_11id_ciba_token",
}


def test_keycloak_outputs_match_independent_catalog_and_ci_owner() -> None:
    catalog = json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text(
        encoding="utf-8"))["secrets"]
    assert EXPECTED == set(OUTPUTS)
    assert EXPECTED <= set(catalog)
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "--image marty-openbao-didcomm:ci --profile selfhost-keycloak" in workflow
    assert "-- python3 scripts/provision_selfhost_keycloak_kms.py" in workflow


def test_keycloak_output_refuses_overwrite_missing_or_private_material(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    values = {name: f"scope-{name}" for name in EXPECTED}
    values["keycloak_master_rs256_cert"] = "-----BEGIN CERTIFICATE-----\npublic\n"
    values["keycloak_11id_rs256_cert"] = "-----BEGIN CERTIFICATE-----\npublic\n"
    with pytest.raises(RuntimeError, match="omit a secret"):
        write_outputs(tmp_path, {"keycloak_signing_kms_token": "scoped"})
    assert list(tmp_path.iterdir()) == []
    values["keycloak_signing_kms_token"] = "-----BEGIN PRIVATE KEY-----\nsecret\n"
    with pytest.raises(RuntimeError, match="private or empty"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []
    values["keycloak_signing_kms_token"] = "scoped-signing-token"
    write_outputs(tmp_path, values)
    assert {path.name for path in tmp_path.iterdir()} == EXPECTED
    with pytest.raises(RuntimeError, match="must be empty"):
        write_outputs(tmp_path, values)


def test_keycloak_output_rejects_unrelated_existing_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    marker = tmp_path / "operator-note"
    marker.write_text("keep me", encoding="ascii")
    values = {name: f"scope-{name}" for name in EXPECTED}
    with pytest.raises(RuntimeError, match="must be empty"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == [marker]
    assert marker.read_text(encoding="ascii") == "keep me"


def test_keycloak_output_rolls_back_only_files_created_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    values = {name: f"scope-{name}" for name in EXPECTED}
    original = os.open
    calls = 0

    def fail_after_three(path: Path, flags: int, mode: int = 0o777) -> int:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("synthetic disk failure")
        return original(path, flags, mode)

    with monkeypatch.context() as patch:
        patch.setattr("provision_selfhost_keycloak_kms.os.open", fail_after_three)
        with pytest.raises(OSError, match="synthetic disk failure"):
            write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="Unix ownership and mode contract")
def test_keycloak_output_requires_owner_private_directory(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    values = {name: f"scope-{name}" for name in EXPECTED}
    with pytest.raises(RuntimeError, match="owner-private"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []


class Mounts:
    def __init__(self, didcomm: str) -> None:
        self.didcomm = didcomm

    def request(self, method: str, path: str) -> dict:
        assert (method, path) == ("GET", "sys/mounts")
        return {"data": {"transit/": {"type": "transit"},
                         "didcomm/": {"type": self.didcomm}}}


def test_keycloak_provisioning_requires_current_didcomm_plugin() -> None:
    require_mounts(Mounts("openbao-didcomm-authcrypt"))
    with pytest.raises(RuntimeError, match="reviewed Keycloak mounts"):
        require_mounts(Mounts("kv"))
    assert PLUGIN_IMAGE.fullmatch("marty-openbao-didcomm:ci")
    assert PLUGIN_IMAGE.fullmatch("marty-openbao-didcomm:local")
    assert not PLUGIN_IMAGE.fullmatch("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm:latest")
