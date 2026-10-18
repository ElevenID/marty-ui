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
from generate_selfhost_disposable_credentials import (  # noqa: E402
    GENERATED, OPERATOR_PASSWORD_POLICY, generate, generate_operator_password,
    validate_operator_password, write_operator_password,
)
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


def test_operator_generator_matches_shipped_policy_without_probabilistic_classes() -> None:
    realm = json.loads((ROOT / "config/keycloak/11id-realm.json").read_text())
    assert realm["passwordPolicy"] == OPERATOR_PASSWORD_POLICY
    assert OPERATOR_PASSWORD_POLICY == "length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)"
    for material in ("0" * 64, "a" * 64, "f" * 64):
        requested = []
        password = generate_operator_password(lambda size: requested.append(size) or material)
        assert requested == [32]
        assert password.endswith(material)
        validate_operator_password(password)


@pytest.mark.parametrize("value", [
    "Aa1!abc", "lowercase123!", "UPPERCASE123!", "Upperlower!", "Upperlower123",
])
def test_invalid_operator_classes_fail_without_disclosing_password(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        validate_operator_password(value)
    assert str(caught.value) == "synthetic operator password does not satisfy the shipped realm policy"
    assert value not in str(caught.value)


def test_operator_policy_drift_and_invalid_randomness_fail_closed(tmp_path: Path) -> None:
    realm = tmp_path / "realm.json"
    realm.write_text(json.dumps({"passwordPolicy": OPERATOR_PASSWORD_POLICY + " and notUsername"}))
    with pytest.raises(ValueError, match="policy needs review"):
        validate_operator_password("Aa1!" + "a" * 64, realm)
    with pytest.raises(ValueError, match="invalid material"):
        generate_operator_password(lambda _: "private-invalid-value")
    realm.write_text("{unparseable-public-realm}")
    with pytest.raises(ValueError, match="policy is unavailable"):
        validate_operator_password("Aa1!" + "a" * 64, realm)


def test_operator_generator_validates_explicit_source_realm(tmp_path: Path) -> None:
    realm = tmp_path / "realm.json"
    realm.write_text(json.dumps({"passwordPolicy": OPERATOR_PASSWORD_POLICY}))
    assert generate_operator_password(lambda _: "a" * 64, realm_file=realm) == "Aa1!" + "a" * 64
    realm.write_text(json.dumps({"passwordPolicy": "length(8)"}))
    with pytest.raises(ValueError, match="policy needs review"):
        generate_operator_password(lambda _: "a" * 64, realm_file=realm)


@pytest.mark.skipif(os.name != "posix", reason="POSIX private file modes")
def test_operator_password_file_is_private_and_never_overwrites(tmp_path: Path, capsys) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "operator-password"
    write_operator_password(output)
    original = output.read_text(encoding="ascii")
    validate_operator_password(original.strip())
    assert output.stat().st_mode & 0o777 == 0o600
    assert not capsys.readouterr().out
    with pytest.raises(FileExistsError):
        write_operator_password(output)
    assert output.read_text(encoding="ascii") == original
    linked = tmp_path / "linked-password"
    linked.symlink_to(output)
    with pytest.raises(FileExistsError):
        write_operator_password(linked)
    assert output.read_text(encoding="ascii") == original


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


@pytest.mark.skipif(os.name != "posix", reason="POSIX private file modes")
def test_generates_distinct_private_values_without_overwriting(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    existing = tmp_path / "operator-owned"
    existing.write_text("preserve", encoding="ascii")
    generate(tmp_path)
    values = {(tmp_path / name).read_text(encoding="ascii") for name in GENERATED}
    assert len(values) == len(GENERATED)
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in values)
    assert existing.read_text(encoding="ascii") == "preserve"
    assert all((tmp_path / name).stat().st_mode & 0o777 == 0o444 for name in GENERATED)
    with pytest.raises(ValueError, match="overwrite"):
        generate(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX private file modes")
def test_rejects_reused_or_malformed_randomness_before_writing(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    with pytest.raises(ValueError, match="invalid or reused"):
        generate(tmp_path, lambda _: "a" * 64)
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError, match="invalid or reused"):
        generate(tmp_path, lambda _: "not-a-key")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX private file modes")
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


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode transition")
def test_rolls_back_if_readable_mode_cannot_be_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    existing = tmp_path / "operator-owned"
    existing.write_text("preserve", encoding="ascii")
    real_fchmod = os.fchmod
    calls = 0

    def fail_fourth(descriptor: int, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("synthetic mode failure")
        real_fchmod(descriptor, mode)

    with monkeypatch.context() as patch:
        patch.setattr("generate_selfhost_disposable_credentials.os.fchmod", fail_fourth)
        with pytest.raises(OSError, match="synthetic mode failure"):
            generate(tmp_path)
    assert list(tmp_path.iterdir()) == [existing]
    assert existing.read_text(encoding="ascii") == "preserve"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_rejects_permissive_root(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="owner-private"):
        generate(tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name == "posix", reason="native non-POSIX refusal")
def test_rejects_non_posix_host(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="POSIX host"):
        generate(tmp_path)
