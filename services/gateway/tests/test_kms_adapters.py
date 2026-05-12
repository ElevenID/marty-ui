"""Tests for the KMS adapter module (GAP-003-h)."""
from __future__ import annotations

import base64
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.kms_adapters import (
    AwsKmsAdapter,
    CapabilityResult,
    AzureKeyVaultAdapter,
    GcpCloudKmsAdapter,
    OpenBaoTransitAdapter,
    der_to_raw_ecdsa,
    get_adapter,
)


# ---------------------------------------------------------------------------
# der_to_raw_ecdsa
# ---------------------------------------------------------------------------


def _encode_der_sig(r: int, s: int, key_size: int = 32) -> bytes:
    """Build a minimal DER SEQUENCE { INTEGER r, INTEGER s }."""

    def _encode_int(n: int) -> bytes:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return bytes([0x02, len(raw)]) + raw

    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    body = r_enc + s_enc
    return bytes([0x30, len(body)]) + body


def test_der_to_raw_ecdsa_round_trip():
    """DER → raw should produce key_size*2 bytes with correct r/s values."""
    r = 0xDEADBEEF * (2 ** 200)
    s = 0xCAFEBABE * (2 ** 200)
    der = _encode_der_sig(r, s, key_size=32)
    raw = der_to_raw_ecdsa(der, key_size_bytes=32)
    assert len(raw) == 64
    assert int.from_bytes(raw[:32], "big") == r % (2 ** 256)
    assert int.from_bytes(raw[32:], "big") == s % (2 ** 256)


def test_der_to_raw_ecdsa_strips_leading_zero():
    """Integers with a leading zero byte (high-bit set) should decode correctly."""
    # r has a leading 0x00 in DER because its MSB is set
    r = 2 ** 255 + 1
    s = 1
    der = _encode_der_sig(r, s, key_size=32)
    raw = der_to_raw_ecdsa(der, key_size_bytes=32)
    assert len(raw) == 64


def test_der_to_raw_ecdsa_raises_on_bad_tag():
    with pytest.raises(ValueError, match="0x30"):
        der_to_raw_ecdsa(b"\x01\x02\x03\x04")


def test_der_to_raw_ecdsa_raises_on_missing_integer():
    # Valid SEQUENCE start but no INTEGER inside
    with pytest.raises(ValueError, match="0x02"):
        der_to_raw_ecdsa(b"\x30\x04\x01\x02\x01\x02")


# ---------------------------------------------------------------------------
# CapabilityResult
# ---------------------------------------------------------------------------


def test_capability_result_add_check():
    result = CapabilityResult(ok=True)
    result.add_check("Foo", "pass", "All good")
    assert result.checks == [{"name": "Foo", "status": "pass", "detail": "All good", "source": "adapter"}]


# ---------------------------------------------------------------------------
# get_adapter factory
# ---------------------------------------------------------------------------


def test_get_adapter_returns_openbao_for_transit():
    adapter = get_adapter({"service_type": "openbao-transit"})
    assert adapter is not None
    assert isinstance(adapter, OpenBaoTransitAdapter)


def test_get_adapter_returns_same_adapter_for_vault_transit():
    adapter = get_adapter({"service_type": "hashicorp-vault-transit"})
    assert adapter is not None
    assert isinstance(adapter, OpenBaoTransitAdapter)


def test_get_adapter_returns_aws_adapter():
    adapter = get_adapter({"service_type": "aws-kms"})
    assert isinstance(adapter, AwsKmsAdapter)


def test_get_adapter_returns_azure_adapter():
    adapter = get_adapter({"service_type": "azure-key-vault"})
    assert isinstance(adapter, AzureKeyVaultAdapter)


def test_get_adapter_returns_gcp_adapter():
    adapter = get_adapter({"service_type": "gcp-cloud-kms"})
    assert isinstance(adapter, GcpCloudKmsAdapter)


def test_get_adapter_returns_none_for_unknown():
    adapter = get_adapter({"service_type": "unknown-provider"})
    assert adapter is None


# ---------------------------------------------------------------------------
# OpenBaoTransitAdapter.verify_connection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openbao_verify_connection_success():
    adapter = OpenBaoTransitAdapter()
    config = {
        "endpoint": "http://openbao:8200",
        "mount": "transit",
        "key_reference": "cred-issuer",
        "auth_reference": "root",
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"supports_signing": True, "latest_version": 1, "keys": {"1": {}}}
    }

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(config)

    assert result.ok is True
    assert any(c["status"] == "pass" for c in result.checks)


@pytest.mark.asyncio
async def test_openbao_verify_connection_returns_fail_on_403():
    adapter = OpenBaoTransitAdapter()
    config = {"endpoint": "http://openbao:8200", "mount": "transit", "key_reference": "key", "auth_reference": "bad"}

    mock_response = MagicMock()
    mock_response.status_code = 403

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(config)

    assert result.ok is False
    assert any(c["status"] == "fail" and "Token" in c["detail"] for c in result.checks)


@pytest.mark.asyncio
async def test_openbao_verify_connection_returns_fail_on_404():
    adapter = OpenBaoTransitAdapter()
    config = {"endpoint": "http://openbao:8200", "mount": "transit", "key_reference": "missing", "auth_reference": "tok"}

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(config)

    assert result.ok is False
    assert any("not found" in c["detail"] for c in result.checks)


@pytest.mark.asyncio
async def test_openbao_verify_connection_fails_when_no_endpoint():
    adapter = OpenBaoTransitAdapter()
    result = await adapter.verify_connection({"mount": "transit", "key_reference": "key"})
    assert result.ok is False
    assert any(c["name"] == "Endpoint" for c in result.checks)


@pytest.mark.asyncio
async def test_openbao_verify_connection_handles_connect_error():
    import httpx

    adapter = OpenBaoTransitAdapter()
    config = {"endpoint": "http://unreachable:9999", "mount": "transit", "key_reference": "key", "auth_reference": "tok"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        result = await adapter.verify_connection(config)

    assert result.ok is False
    assert any("Cannot reach" in c["detail"] for c in result.checks)


# ---------------------------------------------------------------------------
# OpenBaoTransitAdapter.sign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openbao_sign_returns_decoded_bytes():
    adapter = OpenBaoTransitAdapter()
    config = {
        "endpoint": "http://openbao:8200",
        "mount": "transit",
        "key_reference": "cred-issuer",
        "auth_reference": "root",
    }
    raw_sig = b"\xde\xad\xbe\xef" * 16
    vault_sig = "vault:v1:" + base64.b64encode(raw_sig).decode()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"signature": vault_sig}}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        result = await adapter.sign(config, b"hello world")

    assert result == raw_sig


@pytest.mark.asyncio
async def test_openbao_sign_raises_when_missing_endpoint():
    adapter = OpenBaoTransitAdapter()
    with pytest.raises(ValueError, match="endpoint"):
        await adapter.sign({"mount": "transit", "key_reference": "key"}, b"data")


# ---------------------------------------------------------------------------
# AwsKmsAdapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aws_sign_returns_der_signature_from_boto3():
    adapter = AwsKmsAdapter()
    fake_client = MagicMock()
    fake_client.sign.return_value = {"Signature": b"\x30\x06\x02\x01\x01\x02\x01\x02"}

    with patch.object(adapter, "_build_client", return_value=fake_client):
        result = await adapter.sign({"key_reference": "arn:aws:kms:us-east-1:123:key/abc"}, b"payload")

    assert result.startswith(b"\x30")


@pytest.mark.asyncio
async def test_aws_get_public_key_returns_metadata_payload():
    adapter = AwsKmsAdapter()
    fake_client = MagicMock()
    fake_client.get_public_key.return_value = {
        "PublicKey": b"DERBYTES",
        "SigningAlgorithms": ["ECDSA_SHA_256"],
        "KeySpec": "ECC_NIST_P256",
        "KeyUsage": "SIGN_VERIFY",
    }

    with patch.object(adapter, "_build_client", return_value=fake_client):
        result = await adapter.get_public_key_jwk({"key_reference": "arn:aws:kms:us-east-1:123:key/abc"})

    assert result["provider"] == "aws"
    assert result["public_key_der_b64"] == base64.b64encode(b"DERBYTES").decode()


@pytest.mark.asyncio
async def test_aws_verify_connection_fails_without_key_reference():
    adapter = AwsKmsAdapter()
    result = await adapter.verify_connection({"region": "us-east-1"})
    assert result.ok is False
    assert any(c["name"] == "Key reference" for c in result.checks)


def test_aws_build_client_raises_when_boto3_missing(monkeypatch):
    adapter = AwsKmsAdapter()
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(RuntimeError, match="boto3"):
        adapter._build_client({"region": "us-east-1"})


# ---------------------------------------------------------------------------
# AzureKeyVaultAdapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_azure_sign_decodes_base64url_signature():
    adapter = AzureKeyVaultAdapter()
    sig_raw = b"\x30\x06\x02\x01\x01\x02\x01\x02"
    sig_b64url = base64.urlsafe_b64encode(sig_raw).decode().rstrip("=")

    mock_response = MagicMock()
    mock_response.json.return_value = {"value": sig_b64url}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        result = await adapter.sign(
            {
                "endpoint": "https://example.vault.azure.net",
                "key_reference": "issuer-key",
                "auth_reference": "token",
            },
            b"payload",
        )

    assert result == sig_raw


@pytest.mark.asyncio
async def test_azure_get_public_key_returns_embedded_jwk():
    adapter = AzureKeyVaultAdapter()

    mock_response = MagicMock()
    mock_response.json.return_value = {"key": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.get_public_key_jwk(
            {
                "endpoint": "https://example.vault.azure.net",
                "key_reference": "issuer-key",
                "auth_reference": "token",
            }
        )

    assert result["provider"] == "azure"
    assert result["kty"] == "EC"


@pytest.mark.asyncio
async def test_azure_verify_connection_handles_401():
    adapter = AzureKeyVaultAdapter()

    mock_response = MagicMock()
    mock_response.status_code = 401

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(
            {
                "endpoint": "https://example.vault.azure.net",
                "key_reference": "issuer-key",
                "auth_reference": "token",
            }
        )

    assert result.ok is False
    assert any(c["name"] == "Authentication" for c in result.checks)


# ---------------------------------------------------------------------------
# GcpCloudKmsAdapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gcp_sign_decodes_signature_field():
    adapter = GcpCloudKmsAdapter()
    sig_raw = b"\x30\x06\x02\x01\x03\x02\x01\x04"

    mock_response = MagicMock()
    mock_response.json.return_value = {"signature": base64.b64encode(sig_raw).decode()}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        result = await adapter.sign(
            {
                "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "auth_reference": "token",
            },
            b"payload",
        )

    assert result == sig_raw


@pytest.mark.asyncio
async def test_gcp_get_public_key_returns_metadata():
    adapter = GcpCloudKmsAdapter()

    mock_response = MagicMock()
    mock_response.json.return_value = {"pem": "-----BEGIN PUBLIC KEY-----", "algorithm": "EC_SIGN_P256_SHA256"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.get_public_key_jwk(
            {
                "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "auth_reference": "token",
            }
        )

    assert result["provider"] == "gcp"
    assert result["algorithm"] == "EC_SIGN_P256_SHA256"


# ---------------------------------------------------------------------------
# OpenBaoTransitAdapter.get_public_key_jwk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openbao_get_public_key_returns_pem_and_ref():
    adapter = OpenBaoTransitAdapter()
    config = {
        "endpoint": "http://openbao:8200",
        "mount": "transit",
        "key_reference": "cred-issuer",
        "auth_reference": "root",
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "latest_version": 2,
            "keys": {
                "2": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n"}
            },
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.get_public_key_jwk(config)

    assert result["provider"] == "openbao"
    assert result["key_reference"] == "cred-issuer"
    assert "MFk=" in result["public_key_pem"]


@pytest.mark.asyncio
async def test_openbao_get_public_key_raises_when_missing_endpoint():
    adapter = OpenBaoTransitAdapter()
    with pytest.raises(ValueError, match="endpoint"):
        await adapter.get_public_key_jwk({"mount": "transit", "key_reference": "key"})


# ---------------------------------------------------------------------------
# AzureKeyVaultAdapter — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_azure_sign_raises_when_endpoint_missing():
    adapter = AzureKeyVaultAdapter()
    with pytest.raises(ValueError, match="endpoint"):
        await adapter.sign({"key_reference": "mykey"}, b"data")


@pytest.mark.asyncio
async def test_azure_get_public_key_raises_when_key_reference_missing():
    adapter = AzureKeyVaultAdapter()
    with pytest.raises(ValueError, match="key_reference"):
        await adapter.get_public_key_jwk({"endpoint": "https://vault.azure.net"})


@pytest.mark.asyncio
async def test_azure_verify_connection_fails_when_endpoint_missing():
    adapter = AzureKeyVaultAdapter()
    result = await adapter.verify_connection({})
    assert result.ok is False
    assert any(c["name"] == "Endpoint" for c in result.checks)


# ---------------------------------------------------------------------------
# GcpCloudKmsAdapter — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gcp_sign_raises_when_key_reference_missing():
    adapter = GcpCloudKmsAdapter()
    with pytest.raises(ValueError, match="key_reference"):
        await adapter.sign({}, b"data")


@pytest.mark.asyncio
async def test_gcp_get_public_key_raises_when_key_reference_missing():
    adapter = GcpCloudKmsAdapter()
    with pytest.raises(ValueError, match="key_reference"):
        await adapter.get_public_key_jwk({})


@pytest.mark.asyncio
async def test_gcp_verify_connection_fails_when_key_reference_missing():
    adapter = GcpCloudKmsAdapter()
    result = await adapter.verify_connection({})
    assert result.ok is False
    assert any(c["name"] == "Key reference" for c in result.checks)


@pytest.mark.asyncio
async def test_gcp_verify_connection_fails_on_401():
    adapter = GcpCloudKmsAdapter()

    mock_response = MagicMock()
    mock_response.status_code = 401

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(
            {
                "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "auth_reference": "bad-token",
            }
        )

    assert result.ok is False
    assert any(c["name"] == "Authentication" for c in result.checks)


@pytest.mark.asyncio
async def test_gcp_verify_connection_succeeds_on_200():
    adapter = GcpCloudKmsAdapter()

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(
            {
                "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "auth_reference": "token",
            }
        )

    assert result.ok is True
    assert any(c["status"] == "pass" for c in result.checks)


# ---------------------------------------------------------------------------
# AwsKmsAdapter — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aws_sign_raises_when_key_reference_missing():
    adapter = AwsKmsAdapter()
    with pytest.raises(ValueError, match="key_reference"):
        await adapter.sign({}, b"data")


@pytest.mark.asyncio
async def test_aws_get_public_key_raises_when_key_reference_missing():
    adapter = AwsKmsAdapter()
    with pytest.raises(ValueError, match="key_reference"):
        await adapter.get_public_key_jwk({})


@pytest.mark.asyncio
async def test_aws_verify_connection_reports_error_on_boto3_exception():
    adapter = AwsKmsAdapter()

    fake_client = MagicMock()
    fake_client.describe_key.side_effect = Exception("AccessDeniedException")

    with patch.object(adapter, "_build_client", return_value=fake_client):
        result = await adapter.verify_connection({"key_reference": "arn:aws:kms:us-east-1:123:key/abc"})

    assert result.ok is False
    assert any("AWS KMS" in c["detail"] for c in result.checks)


@pytest.mark.asyncio
async def test_gcp_verify_connection_fails_on_404():
    adapter = GcpCloudKmsAdapter()

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await adapter.verify_connection(
            {
                "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "auth_reference": "token",
            }
        )

    assert result.ok is False
    assert any(c["name"] == "Key exists" for c in result.checks)
