from pathlib import Path
import runpy

import pytest


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))


def test_selfhost_holder_credential_is_long_and_dedicated(tmp_path: Path) -> None:
    values = {
        "device_registration_signing_keys_key": "holder-credential-" + "h" * 32,
        "device_registration_gateway_key": "gateway-credential-" + "g" * 32,
        "grpc_service_token": "grpc-credential-" + "r" * 32,
        "issuance_api_key": "issuance-credential-" + "i" * 32,
    }
    for name, value in values.items():
        (tmp_path / name).write_text(value, encoding="utf-8")
    validate = PREFLIGHT["validate_holder_service_credential"]
    assert "separation verified" in validate(tmp_path)

    (tmp_path / "device_registration_signing_keys_key").write_text("short", encoding="utf-8")
    with pytest.raises(PREFLIGHT["CheckError"], match="at least 32 bytes"):
        validate(tmp_path)

    for name in ("device_registration_gateway_key", "grpc_service_token", "issuance_api_key"):
        (tmp_path / "device_registration_signing_keys_key").write_text(values[name], encoding="utf-8")
        with pytest.raises(PREFLIGHT["CheckError"], match="must be dedicated"):
            validate(tmp_path)


def test_selfhost_issuer_signing_credential_is_long_and_dedicated(tmp_path: Path) -> None:
    values = {
        "signing_keys_issuer_sign_key": "issuer-credential-" + "e" * 32,
        "signing_keys_service_sign_gateway_key": "service-credential-" + "s" * 32,
        "device_registration_signing_keys_key": "holder-credential-" + "h" * 32,
        "device_registration_gateway_key": "gateway-credential-" + "g" * 32,
        "grpc_service_token": "grpc-credential-" + "r" * 32,
        "issuance_api_key": "issuance-credential-" + "i" * 32,
    }
    for name, value in values.items():
        (tmp_path / name).write_text(value, encoding="utf-8")
    validate = PREFLIGHT["validate_issuer_sign_credential"]
    assert "separation verified" in validate(tmp_path)

    (tmp_path / "signing_keys_issuer_sign_key").write_text("short", encoding="utf-8")
    with pytest.raises(PREFLIGHT["CheckError"], match="at least 32 bytes"):
        validate(tmp_path)

    for name in values.keys() - {"signing_keys_issuer_sign_key"}:
        (tmp_path / "signing_keys_issuer_sign_key").write_text(values[name], encoding="utf-8")
        with pytest.raises(PREFLIGHT["CheckError"], match="must be dedicated"):
            validate(tmp_path)


def test_selfhost_signing_grants_cannot_reuse_an_origin_or_provider_token(tmp_path: Path) -> None:
    grant_files = (
        "sign_grant_verify_token",
        "sign_grant_mint_flow_wallet_token",
        "sign_grant_mint_gateway_service_token",
        "sign_grant_mint_gateway_issuer_did_token",
        "sign_grant_mint_issuance_credential_token",
        "sign_grant_mint_issuance_canvas_token",
        "sign_grant_mint_issuance_readiness_token",
        "sign_grant_mint_issuance_passport_token",
    )
    provider_files = (
        "openbao_service_token",
        "openbao_bootstrap_token",
        "signing_keys_openbao_token",
        "didcomm_issuance_openbao_token",
        "haip_kms_token",
        "notification_openbao_token",
    )
    for index, name in enumerate((*grant_files, *provider_files)):
        (tmp_path / name).write_text(f"disposable-token-{index}", encoding="utf-8")
    validate = PREFLIGHT["validate_signing_grant_credentials"]
    assert "distinct" in validate(tmp_path)

    for name, source in (
        (grant_files[1], grant_files[0]),
        (provider_files[0], grant_files[0]),
        (provider_files[1], provider_files[0]),
    ):
        duplicate = (tmp_path / source).read_text(encoding="utf-8")
        previous = (tmp_path / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(duplicate, encoding="utf-8")
        with pytest.raises(PREFLIGHT["CheckError"], match="must be distinct") as error:
            validate(tmp_path)
        assert duplicate not in str(error.value)
        (tmp_path / name).write_text(previous, encoding="utf-8")
