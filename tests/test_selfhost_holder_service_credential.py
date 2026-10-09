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
