"""Disposable text credentials cannot stand in for managed KMS material."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from generate_selfhost_disposable_credentials import GENERATED, generate  # noqa: E402
from run_selfhost_business_journey import LOCAL_SECRET_NAMES  # noqa: E402


EXPECTED = {
    "device_registration_gateway_key", "device_registration_signing_keys_key",
    "flow_application_event_hmac_key", "flow_webhook_secret", "grpc_service_token",
    "issuance_api_key", "keycloak_admin_password", "keycloak_db_password",
    "marty_api_client_secret", "marty_db_password",
    "notification_applicant_event_token", "notification_webhook_secret",
    "postgres_password", "signing_keys_integration_secret_key",
    "signing_keys_issuer_sign_key", "signing_keys_service_sign_gateway_key",
    "token_hmac_key",
}


def test_generated_names_match_local_catalog_without_managed_keys() -> None:
    catalog = json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text(
        encoding="utf-8"))["secrets"]
    assert GENERATED == EXPECTED
    assert GENERATED <= LOCAL_SECRET_NAMES
    assert all(name in catalog and catalog[name]["compose_secret"] == name
               for name in GENERATED)
    assert not any(name.endswith("_tls_kms_token") or "workload" in name
                   or name.startswith("keycloak_11id_")
                   or name in {"haip_kms_token", "openbao_tls_ca_cert"}
                   for name in GENERATED)


def test_generates_distinct_private_values_without_overwriting(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    existing = tmp_path / "operator-owned"
    existing.write_text("preserve", encoding="ascii")
    generate(tmp_path)
    values = {(tmp_path / name).read_text(encoding="ascii") for name in GENERATED}
    assert len(values) == len(GENERATED)
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in values)
    assert existing.read_text(encoding="ascii") == "preserve"
    if os.name != "nt":
        assert all((tmp_path / name).stat().st_mode & 0o077 == 0 for name in GENERATED)
    with pytest.raises(ValueError, match="overwrite"):
        generate(tmp_path)


def test_rejects_reused_or_malformed_randomness_before_writing(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    with pytest.raises(ValueError, match="invalid or reused"):
        generate(tmp_path, lambda _: "a" * 64)
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError, match="invalid or reused"):
        generate(tmp_path, lambda _: "not-a-key")
    assert list(tmp_path.iterdir()) == []


def test_rolls_back_only_new_files_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    existing = tmp_path / "operator-owned"
    existing.write_text("preserve", encoding="ascii")
    real_open = os.open
    calls = 0

    def fail_fourth(path: Path, flags: int, mode: int = 0o777) -> int:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("synthetic disk failure")
        return real_open(path, flags, mode)

    with monkeypatch.context() as patch:
        patch.setattr("generate_selfhost_disposable_credentials.os.open", fail_fourth)
        with pytest.raises(OSError, match="synthetic disk failure"):
            generate(tmp_path)
    assert list(tmp_path.iterdir()) == [existing]
    assert existing.read_text(encoding="ascii") == "preserve"


@pytest.mark.skipif(os.name == "nt", reason="Unix ownership and mode contract")
def test_rejects_permissive_root(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="owner-private"):
        generate(tmp_path)
    assert list(tmp_path.iterdir()) == []
